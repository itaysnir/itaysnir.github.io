---
layout: post
title:  "Networking Kernel Configuration Notes"
date:   2022-11-07 19:59:43 +0300
categories: jekyll update
---

**Contents**
* TOC
{:toc}
## Kernel Command Line


For reliable measurements, it is important to disable security features, such as Spectre and Meltdown hardenings.
There are many more arguments we shall disable, for example iommu usage. 

Open `/etc/default/grub`, and add:
```bash
GRUB_CMDLINE_LINUX="noibrs noibpb mds=off tsx_async_abort=off nx_huge_pages=off nospectre_v1 spec_store_bypass_disable=off intel_iommu=off pti=off spectre_v2=off l1tf=off nospec_store_bypass_disable no_stf_barrier intel_pstate=disable mitigations=off idle=poll"
```

Afterwards, issue `update-grub`, and reboot the configured kernel. 
Finally, read `/proc/cmdline` to verify the configuration have completed succesfully. 
