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
The full code can be found at [itay-maio-github][github].

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

## Source Code

Can be found [here][github].

The following new files are added: 

1. `linux/maio.h` - contains the kernel API for maio. \
Its source is under `lib/maio.c`. \
Notice that currently maio should support multiple network device, as `maio_post_rx_page` also receives a `struct netdevice *net` argument. \
It also supports [napi][napi-wiki], via `maio_napi`. 

2. `linux/magazine.h` - dedicated magazine page allocator. \
Its source is under `lib/magazine.c`. 
   
3. `lib/Makefile` - compiles maio and the dedicated magazine allocator as kernel-builtins. \
Notice the compilation is currently made via `obj-y`, and not according to the kernel's config settings.

Moreover, maio also changes the following core-kernel functionality:

1. `linux/mm.h` - Added logic for maio-pages allocation and deallocation. 

2. `linux/mm_types.h` - patched `struct page`, so that it keeps track of the amount of compound pages. 

3. `linux/page-flags.h` - the method `compund_head(struct page *page)` is patched, to allow verbose debug info. 

4. `linux/skbuff.h` - patches `__skb_frag_ref`, so it would increase the refcount of the relevant dedicated maio page, instead of regular `get_page(skb_frag_page(frag))` call.
   
5. `net/core/skbuff.c` - patches `skb_gro_receive, skb_try_coalesce` to use maio virtual addressing translation to compound head page, instead of regular page's `virt_to_head_page(skb->head)`. 

6. `mm/page_alloc.c` - adjusted to free maio pages correctly. 

7. `mm/swap.c` - the `put_page` family is adjusted, so that maio pages are freed correctly. \
maio pages are consturcted from compound-pages, so only `__put_compound_page` should be patched. 

8. `drivers/net/ethernet/mellanox/mlx5/core/en_rx.c` - adjuses the mellanox NIC driver to use maio's kernel API. \
This includes patching the `mlx5e_page_alloc_pool` method, so it would allocate and release maio pages for `dma_info->page`. 

9. `drivers/net/ethernet/mellanox/mlx4/en_netdev.c` - added similar mlx4 support. 
    
10. `drivers/net/hyperv/netvsc_drv.c` - added maio copy support for netvsc. 

The following changes are made for easier debugging:

1. `drivers/net/ethernet/mellanox/mlx5/core/en/params.c` - added call for debug printing of the `sw_mtu, hw_mtu` values. 

2. `drivers/net/ethernet/mellanox/mlx5/core/en_main.c` - The method `mlx5e_init_frags_partition` prints the fragmented packet details. 

## Notes

Currently theres no support for multiple sends, due to added `set_page_state` for single-page call under `lib/maio.c`. 

Also verify the `maio_*_free` methods are implemented correctly, and not as nops. 


[github]: https://github.com/itaysnir/maio_rfc
[napi-wiki]: https://en.wikipedia.org/wiki/New_API
