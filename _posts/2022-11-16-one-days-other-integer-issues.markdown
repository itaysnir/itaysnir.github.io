---
layout: post
title:  "One Days - Other Integer Issues"
date:   2022-11-20 20:00:01 +0300
categories: jekyll update
---

**Contents**
* TOC
{:toc}
## Background

### Incorrect signed sanity checks

Trivial example:

```c
int size = strtoul(argv[1], NULL, 16);
if (size > 100)
{
    printf("Nice try\n");
    return;
}

memcpy(buf, argv[2], size);
```

Of course, this is bypass-able as attacker enters a negative value. `memcpy` treats the `size` variable as an unsigned integer, hence producing overflow. 


### Integer Truncation

```c
unsigned int size ;
...
unsigned short alloc_size = size;  // stores only the lowest 2 bytes
```

Allocation via `size = 0x10000` would lead to `alloc_size = 0`. 


### Signed Integer Extensions 

Holds for signed integers. 

```c
char buf[0x10000];
char *ptr1;
short size1 = 0x8000;

ptr1 = buf + size1;  // Actually DECREASES by 0x8000 bytes!
```

Since the MSB is '1', the signed integer actually represents a negative number. 

Hence, it will actually perform an OOB-underflow!


## CVE-2019-15948 - TI Bluetooth


### Code

```c
////ACID: where ptr_ll_pkt points after assignment
// Pseudocode from Ghidra decompilation
void process_adv_ind_pdu(int ptr_some_struct)
{
  byte bVar1;
  byte ll_len;
  uint n;
  uint uVar2;
  byte *ptr_ll_pkt;
  undefined local_40;
  byte local_3f;
  undefined auStack62 [0x6];
  undefined local_38;
  undefined stack_buffer [0x1f];
  undefined local_18;

  ptr_ll_pkt = (byte *)(DAT_0005b528 + (uint)*(ushort *)(ptr_some_struct + 0x8));
  bVar1 = *ptr_ll_pkt;
  ll_len = ptr_ll_pkt[0x1];
  uVar2 = (uint)bVar1 & 0xf;
  local_3f = (byte)(((uint)bVar1 << 0x19) >> 0x1f);
  FUN_00067554(auStack62,ptr_ll_pkt + 0x2,0x6);
  n = ((uint)ll_len & 0x3f) - 0x6 & 0xff;
  local_38 = (undefined)n;
  memcpy(stack_buffer,ptr_ll_pkt + 0x8,n);
  local_18 = *(undefined *)(ptr_some_struct + 0xa);
  if ((bVar1 & 0xf) == 0x0) {
    local_40 = 0x0;
  }
  else {
    if (uVar2 == 0x1) {
      local_40 = 0x1;
      local_38 = 0x0;
    }
    else {
      if (uVar2 == 0x2) {
        local_40 = 0x3;
      }
      else {
        if (uVar2 != 0x6) {
          return;
        }
        local_40 = 0x2;
      }
    }
  }
  FUN_000398e2(0x1,&local_40);
  return;
}
```

### Code Review

1. `n` is correctly defined as an uint. 

However, its calculation enables a value as large as 0xff bytes:

```c
n = ((uint)ll_len & 0x3f) - 0x6 & 0xff;
```

Since `ll_len` is attacker controlled, it may be set to 5, which would underflow, and due to truncation `n` would be set to 0xff bytes.

2. Stack buffer overflow:

```c
memcpy(stack_buffer,ptr_ll_pkt + 0x8,n);
```

Since `stack_buffer` is only 0x1f bytes long, a value of `n = 0xff` enables a stack overflow. 

### Patch

No released patch.


## CVE-2019-14196 - u-boot NFS

### Code

```c
// Globals
static char filefh[NFS3_FHSIZE]; /* NFSv2 / NFSv3 file handle */
static int filefh3_length;	/* (variable) length of filefh when NFSv3 */

////ACID: pkt
static int nfs_lookup_reply(uchar *pkt, unsigned len)
{
	struct rpc_t rpc_pkt;

	debug("%s\n", __func__);

	memcpy(&rpc_pkt.u.data[0], pkt, len);

// ...

	if (supported_nfs_versions & NFSV2_FLAG) {
		memcpy(filefh, rpc_pkt.u.reply.data + 1, NFS_FHSIZE);
	} else {  /* NFSV3_FLAG */
		filefh3_length = ntohl(rpc_pkt.u.reply.data[1]);
		if (filefh3_length > NFS3_FHSIZE)
			filefh3_length  = NFS3_FHSIZE;
		memcpy(filefh, rpc_pkt.u.reply.data + 2, filefh3_length);
	}

	return 0;
}
```

### Code Review

1. Only `pkt` is attacker-controlled. 

This means `rpc_pkt.u.data` is controlled.

2. `filefh3_length` defined as a static int, instead of uint. 
Moreover, it is attacker controlled. 

There is an insufficient sanity check:

```c
if (filefh3_length > NFS3_FHSIZE)
	filefh3_length  = NFS3_FHSIZE;
```

As `filefh3_length` might be set to some negative value, hence bypassing the sanity check.

3. Since `memcpy` takes an uint argument, a `.BSS` buffer overflow occurs for negative inputs.

### Patch

The fixes weren't really fixing anything. 


## CVE-2020-15999

