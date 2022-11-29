---
layout: post
title:  "Networking - Kernel Configuration Notes"
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



## Ethtool

The `ethtool` command allows querying and setting NIC driver configuration. 



## IRQ Affinity

### General

Each hardware device may generate IRQs which are handled by the OS.

The idea is pretty simple - cache coherence is shit. If all CPUs would handle all IRQs, we would barely have any caching advantage.

A cache friendly approach, is to have a dedicated core for each IRQ. 

### IRQ Mappings

We can find the mapping between IRQ and its device driver under `/proc/interrupts`. 

This pseudo-file also stores a counter of how many times each IRQ was handled on each core, as well as whether or not it uses an APIC. 

This is important, as only IRQs that uses an APIC may have adjusted affinity.

The affinity of a certain IRQ number can be found under `/proc/irq/<IRQ_NUM>/smp_affinity`.\
This file contains a bitmap, where the rightmost bit describes CPU0 and the leftmost bit, CPU31.

For systems with more than 32 cores, a comma would be separating each 32-cores chunk: `ffff,ffffffff`

Therefore, it should be tweaked so that only a single core may handle this IRQ. 

### Network Interfaces

Each network interface is associated with its IRQs and drivers (e.g. `eth4`). 

The pseudo file describing an interface settings can be found under `/sys/class/net/<interface>`

A single network interface may split for TX, RX or TX+RX queues. Therefore, usually the affinity settings are decided on a per-queue basis. 

Each of the send and receive queues of a certain interface, should be associated with only one core. \
For example, `/sys/class/net/eth4/queues/tx-30/xps_cpus` should have only a single enabled bit - `0000,00002000` for instance. 

The same holds for `rps_cpus` (equivalent affinity for RX flows). 

Important note: some drivers don't register their IRQ numbers within `/proc/interrupts`.

In such cases, their IRQ numbers can be found under `/sys/class/net/<interface>/device/msi_irqs`. 

For more reading, see [this][irq-affinity]

[irq-affinity]: https://greenhost.net/blog/2013/04/10/multi-queue-network-interfaces-with-smp-on-linux/
[cool-paper]: https://dl.acm.org/doi/10.1145/3341301.3359640
