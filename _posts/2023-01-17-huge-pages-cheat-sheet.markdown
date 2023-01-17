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
umount `awk '/hugetlbfs/ {print $2}' /proc/mounts`
```

## Extra Links

[DPDK][dpdk-link]


[dpdk-link]: https://doc.dpdk.org/guides-17.02/linux_gsg/nic_perf_intel_platform.html