---
layout: post
title:  "Networking Kernel Configuration Notes"
date:   2022-11-07 19:59:43 +0300
categories: jekyll update
---

**Contents**
* TOC
{:toc}
## Modern Core Linux Performance Paper


The following [cool paper][cool-paper] describes various mechanisms that were added or altered within the linux kernel for the last 7 years.
It explains the main causes of slowdowns and overheads made by these new mechanisms - which dramatically impact networking performace. 

According to the paper, some of the kernel configurations that can be easily altered:
```bash
CONFIG_PAGE_TABLE_ISOLATION=""           # Kernel page-table isolation (Meltdown patch)
CONFIG_RETPOLINE=""                      # Avoid indirect branch speculation (Spectre patch)
CONFIG_SLAB_FREELIST_RANDOM=""           # SLAB freelist randomization
CONFIG_HARDENED_USERCOPY=""              # Hardened usercopy
CONFIG_MEMCG=""                          # Control group memory controller
CONFIG_TRANSPARENT_HUGEPAGE_ALWAYS=y     # Disabling transparent huge pages
CONFIG_USERFAULTFD=""                    # Userspace page fault handling
CONFIG_CONTEXT_TRACKING_FORCE=""         # Forced context tracking
```


## Kernel Command Line


For reliable measurements, it is important to disable security features, such as Spectre and Meltdown hardenings.
There are many more arguments we shall disable, for example iommu usage. 

Open `/etc/default/grub`, and add:
```bash
GRUB_CMDLINE_LINUX="noibrs noibpb mds=off tsx_async_abort=off nx_huge_pages=off nospectre_v1 spec_store_bypass_disable=off intel_iommu=off pti=off spectre_v2=off l1tf=off nospec_store_bypass_disable no_stf_barrier intel_pstate=disable mitigations=off idle=poll"
```

Afterwards, issue `update-grub`, and reboot the configured kernel. 
Finally, read `/proc/cmdline` to verify the configuration have completed succesfully. 

[cool-paper]: https://dl.acm.org/doi/10.1145/3341301.3359640
