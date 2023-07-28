---
layout: post
title:  "Linux Hugepages Cheat Sheet"
date:   2023-01-17 19:59:43 +0300
categories: jekyll update
---

**Contents**
* TOC
{:toc}
## General

TODO: add a description about these pages, and the hugetlbfs

## Handy Commands

Check maximum allocate-able huge pages:

```bash
sudo cat /proc/sys/vm/nr_hugepages
```

Set maximum allocate-able huge pages:

```bash
sudo echo 2024 > /proc/sys/vm/nr_hugepages
```

Check amount of currently allocated / free huge pages:

```bash
sudo cat /sys/kernel/mm/hugepages/hugepages-2048kB/nr_hugepages
sudo cat /sys/kernel/mm/hugepages/hugepages-2048kB/free_hugepages
```

Check all filesystems that were mounted as `hugetlbfs`:

```bash
mount | grep huge
```

Release all `hugetlbfs` filesystems:

```bash
sudo umount `awk '/hugetlbfs/ {print $2}' /proc/mounts`
```

## Extra Links

[DPDK][dpdk-link], [linux][linux-hugetlb-reserve], [lwn][lwn]


[dpdk-link]: https://doc.dpdk.org/guides-17.02/linux_gsg/nic_perf_intel_platform.html
[linux-hugetlb-reserve]: https://www.kernel.org/doc/html/v5.0/vm/hugetlbfs_reserv.html
[lwn]: https://lwn.net/Articles/375096/#:~:text=Hugetlbfs%20is%20a%20bare%20interface,backing%20regions%20with%20huge%20pages.
