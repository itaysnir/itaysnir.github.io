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

Note that both client and server interfaces should be configured via `ethtool` as follow.

### Ring Buffer Size

The inner socket ring buffer entries count, for both TX and RX.
This value can be adjusted:

```bash
sudo ethtool -G eth4 rx 1024 tx 1024
```

This command sets both ring buffers to 1024 entries. 


### LRO

Stands for *large receive offload*. \
This feature reassembles incoming packets into larger buffers. \
These larger buffers are transmitted to the network stack of the host machine *at once*, leading to better utilization. 

Note - it does *not* mean less packets are being processed. 

For more reading about similar techniques, check [this][tcp-offload].

The feature should be disabled for correct throughput tests (as it reduces dramatically the calculated bandwidth):

```bash
sudo ethtool -K eth4 lro off
```

### GRO

Stands for *generic receive offload*, another offloading technique. \
This feature reassembles small packets into larger onces - thus reducing the number of processed packets. 

The key insight, is that GRO is protocol-dependent (there are many defined GRO types). 

For example, *TCP/IPv4 GRO* for common TCP packets. 

This feature should be enabled:

```bash
sudo ethtool -K eth4 gro on
```

### TSO

Transmit segmentation offload, or TCP segmentation offload, also referred as LSO (large segment offload, or large send offload). 

Instead of the operating system network stack being responsible for breaking a large IP packet into MTU-sized packets, the NIC's driver does it. 

If TSO is enabled on the TX path, it greatly offloads the CPU cycles required to transmit large amount of data. 

In order to see if certain NIC driver supports TSO:

```bash
ethtool -k <interface> | grep "tcp-segmentation-offload"
```

This feature should be enabled.

### GSO

Stands for *generic segmentation offload*. \
This is a generalisation of the TSO concept, for protocols other than TCP. 

The main saving is due to traversing the network stack only once, rather than many times for each super-packet. \
The key idea is to postpone segmentation as late as possible - idealy within the NIC driver. \
The driver would rip the super packet to SGLs, or alternatively load the segments into pre-allocated continious memory to be fed to the NIC (so `sk_buffs` won't be segmented). 

Since not all NIC drivers support these, it is possible to perform segmentation right before entry to the xmit routine - GSO. 

Note that both TSO and GSO are only effective in case the MTU (1500) is significantly less than the maximum IP packet value (64 KB).

This feature should be enabled:

```bash
sudo ethtool -K eth4 gso on
```

For further reading, see [dpdk][dpdk-gso]

### PFC

Stands for *priority-based flow control*. \
This allows selection of traffic flows within a link and pause them, so that output queues associated with these flows do not overflow and drop packets. 

A PFC-enabled queue is a lossless queue. \
When congestion occurs in such a queue on a downstream device, the downstream device instructs the upstream device to stop sending traffic in the queue - hence zero packet loss. 

Note that Ethernet's `PAUSE` packets aren't granular - as they pause all of the traffic (queues) within the interface. \
PFC is more granular, as it allows pausing a specific queue. 

This feature should be enabled:

```bash
sudo ethtool -A <interface> rx on tx on
```

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

For further reading aboit IRQ affinity, see [this][irq-affinity]

## NUMA Nodes (Cores) - PCIe

For NUMA system, there is an importance of the chosen affinity core. \
In order to achieve maximal results, we would like to perform all of our benchmark tests on the same core along with the NIC. 

### lspci

By using `lspci`, we can see the relevant information:

```bash
$ lspci -v 
...
04:00.0 Ethernet controller: Mellanox Technologies MT27800 Family [ConnectX-5]
        Subsystem: Mellanox Technologies MT27800 Family [ConnectX-5]
        Flags: bus master, fast devsel, latency 0, IRQ 88, NUMA node 0
        Memory at 3bffa000000 (64-bit, prefetchable) [size=32M]
        Capabilities: <access denied>
        Kernel driver in use: mlx5_core
        Kernel modules: mlx5_core
```

Note the BDF format: `bus:device.function` (do not confuse with `vendor:device` format). \
Sometimes it is also useful to inspect the bus-layout, as can be found via `lspci -t`. 

From the above sample, we can see the Mellanox NIC is connected to `NUMA node 0`! \
We will use set the affinity to this particular core, in order to get best measurement results. 

Last but not least - notice how `lspci` prints the PCI (bus-physical) memory address of the NIC. \
This means `0x3bffa000000` stands for the physical address of the MMIO space of the NIC. \
This address is generated during the PCI-tree scan during boot time - as the kernel reads the required device's memory size via its BAR register (within the PCIe configuration space), and allocates sufficient region for each device.

Note the non-trivial fact that we've got an MMIO physical address without having any special priviledges. 

In case we would execute `sudo lspci -v`, the NIC's capabilities section would also be printed: \
(For extremely verbose output, consider `sudo lspci -vvv`)

```bash
$ sudo lspci -v 
...
Memory at 3bffa000000 (64-bit, prefetchable) [size=32M]
Capabilities: [60] Express Endpoint, MSI 00
Capabilities: [48] Vital Product Data
Capabilities: [9c] MSI-X: Enable+ Count=64 Masked-
Capabilities: [c0] Vendor Specific Information: Len=18 <?>
Capabilities: [40] Power Management version 3
Capabilities: [100] Advanced Error Reporting
Capabilities: [150] Alternative Routing-ID Interpretation (ARI)
Capabilities: [1c0] Secondary PCI Express
```

The offsets `[60], [48], etc` are offsets in the PCIe config space of the device, not MMIO space. \
Also note `lspci` actually parses this information from `/proc/bus/pci/devices`, which contains some additional information. 

### Sysfs

In my setup, im interested to know the associated node of the `eth4` interface (the interface that is associated with the Mellanox-NIC).

By navigating to `/sys/class/net/eth4/device`, we can read the value of `numa_node`, which would yield `0`, as expected. \
Once again, this means we have to run our benchmarks on core number 0.



[irq-affinity]: https://greenhost.net/blog/2013/04/10/multi-queue-network-interfaces-with-smp-on-linux/
[cool-paper]: https://dl.acm.org/doi/10.1145/3341301.3359640
[tcp-offload]: https://en.wikipedia.org/wiki/TCP_offload_engine
[dpdk-gso]: https://doc.dpdk.org/guides/prog_guide/generic_segmentation_offload_lib.html
