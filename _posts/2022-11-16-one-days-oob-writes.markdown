---
layout: post
title:  "One Days - OOB Writes"
date:   2022-11-16 20:00:01 +0300
categories: jekyll update
---

**Contents**
* TOC
{:toc}
## Common Causes

```c
array[ACID] = ACID 

ptr = base + ACID
*ptr = ACID

ptr = ACID
*ptr = ACID
```

Note: there are cases where OOB is way stronger than regular BOF.
For example, in case of a canary presence - OOB write enables direct assignment of the return address, without corrupting the canary. 

## CVE-2019-10540 - Qualcomm Baseband WiFi

The baseband is a dedicated processor on the chip, that handles wireless capabilities.

For example, Wifi, cellular, bluetooth. 

The main processor runs a linux kernel, which is completely separated from the baseband subsystem. 

### (Pseudo) Code

```c
char GlobalBuffer[10 * 0xB0 + 6];

uint count = 0;

for (unsigned int i = 0 ; i < length ; i+= 0x44)
{
    memcpy(GlobalBuffer + 6 + count * 0xB0, data_ptr + i, 0x44);
    count++;
}
```

### Code Review

1. `length` is controlled by the user, therefore overflows the global buffer. 

2. Note the overflow isn't linear, as it skips by 0xB0 bytes for every 0x44 copied bytes. 

### Patch

No released patch.


## CVE-2020-0938 - Windows 10 Adobe Font Parsing

```c
////ACID: num_master
int SetBlendDesignPositions(void *arg) {
  int num_master;
  Fixed16_16 values[16][15];

  for (num_master = 0; ; num_master++) {
    if (GetToken() != TOKEN_OPEN) {
      break;
    }
    //KC: writes an ACID number (0-15) of ACID values at &values[num_master]
    int values_read = GetOpenFixedArray(&values[num_master], 15);
    SetNumAxes(values_read);
  }

  SetNumMasters(num_master);

  for (int i = 0; i < num_master; i++) {
    procs->BlendDesignPositions(i, &values[i]);
  }

  return 0;
}
```

### Code Review

1. As long as `GetToken()` returns `TOKEN_OPEN`, the first loop iterates, and possibly `num_master` exceeds the size of the allocated fixed-size `values` buffer. 

2. `GetOpenFixedArray` and `SetNumAxes` writes a desired number of values at a given index.

Therefore, an attacker can choose to not write any values at `values[0..15]`, but to write return address beyond `values`.


## CVE-2020-1020 - Another Windows 10 Abode Font

