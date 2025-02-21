---
layout: post
title:  "Pwn College - ARM64"
date:   2024-05-26 19:59:45 +0300
categories: jekyll update
---

**Contents**
* TOC
{:toc}
## Overview

Up to ARMv7, only ARM32 instruction set was supported. It was based on ARMV7-A profile, used mostly in mobile devices and embedded. 
Since ARMv8, both ARM(32-bit) and AArch64(64-bit) are supported. \
In addition to the major ISA addition, 31 general-purpose registers are supported (64-bit wide), instead of previous 16 (32-bit wide). Moreover, ARMv8 introduces multiple exception levels (`EL0 - EL3`), as well as the Trustzone, and HW-based virtualization. \
For this module, I will mainly focus on `ARMv8`. Notice the ARM architecture defines several profiles, each targeting specific use cases - `ARMv8-A` (the most widely used - application, for general purpose application processors such as mobiles and servers. Allows features such as HW virtualization, TrustZone, AArch64 ISA), `ARMv8-R` (real-time profile, doesn't supports AArch64 ISA but only 32-bit operations), and `ARMv8-M` (microcontrollers, also doesn't supports AArch64). 

I've used the following documentations: [A Profile docs][arm-a-docs], [AArch64 ISA][aarch64-instruction-set]

## Thumb Mode

Exists only in ARM32, and refers to a 16-bit instruction set. \
The motivation behind this, is mainly optimiziation of space and performance, and instruction-cache in particular. 
The ARM processor can dynamically switch between the modes at runtime by using the LSb (T-bit) in the `CPSR` register. There are few special 32-bit instructions that were added to thumb-2 (extension), introduced in ARMv5. 







[arm-a-docs]: https://www.arm.com/architecture/learn-the-architecture/a-profile
[aarch64-instruction-set]: https://developer.arm.com/documentation/102374/0101/Overview