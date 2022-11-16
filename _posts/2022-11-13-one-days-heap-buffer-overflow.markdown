---
layout: post
title:  "One Days - Heap Buffer Overflows"
date:   2022-11-16 19:59:43 +0300
categories: jekyll update
---

**Contents**
* TOC
{:toc}
## CVE-2020-0917 - VBS SecureKernel

The attack surface is via the `secure calls` mechanism:
These calls are issued by the regular kernel (VTL0) towards the secured kernel (VTL1).

Each virtual memory data to physical memory layout is described by `struct MDL`. 

It contain the mapped virtual address of the data, its total length (bytes), and a variable-length array of PFNs (which may be scattered within the physical memory, similar to linux's `struct iovec`). 

### Code

By issuing a call from VTL0, the caller kernel control all of the `struct MDL` attributes (except `MappedSystemVA`). 

VTL1 kernel must make enough sanity-checks on the received input. 

```c
// XENO: This struct is not officially documented
// XENO: But this is what people have reverse engineered
struct _MDL {
  struct _MDL      *Next;
  CSHORT           Size;
  CSHORT           MdlFlags;
  struct _EPROCESS *Process;
  PVOID            MappedSystemVa;
  PVOID            StartVa;
  ULONG            ByteCount;
  ULONG            ByteOffset; 
} MDL, *PMDL;
// XENO: Struct is followed by a variable-length array
// XENO: Of physical-address (frame) pointers

#define MmInitializeMdl	(_MemoryDescriptorList,
                         _BaseVa,
                         _Length 
)
{ \
  (_MemoryDescriptorList)->Next = (PMDL) NULL; \
  (_MemoryDescriptorList)->Size = (CSHORT) (sizeof(MDL) + \
    (sizeof(PFN_NUMBER) * ADDRESS_AND_SIZE_TO_SPAN_PAGES(_BaseVa, _Length))); \
  (_MemoryDescriptorList)->MdlFlags = 0; \
  (_MemoryDescriptorList)->StartVa = (PVOID) PAGE_ALIGN(_BaseVa); \
  (_MemoryDescriptorList)->ByteOffset = BYTE_OFFSET(_BaseVa); \
  (_MemoryDescriptorList)->ByteCount = (ULONG) _Length; \
}

PMDL TransferMdl;
NTSTATUS Status;
PMDL UndoMdl;

// Obtain a mapping to the undo MDL.

Status = SkmmMapDataTransfer(DataMdl, //XENO: DataMdl ACID in
                              TransferPfn,
                              SkmmMapRead,
                              &TransferMdl, //XENO: TransferMdl ACID out
                              NULL);

if(!NT_SUCCESS(Status)) {
	return Status;
}

UndoMdl = SkAllocatePool(NonPagedPoolNx, TransferMdl->ByteCount, 'ldmM');

if(UndoMdl == NULL){
	goto CleanupAndExit;
}

OriginalUndoMdl = TransferMdl->MappedSystemVa; //XENO: Attacker controls data at address, not address itself
MmInitializeMdl(UndoMdl, (PVOID)OriginalUndoMdl->ByteOffset, OriginalUndoMdl->ByteCount);
```

### Code Review

1. `MmInitializeMdl` macro have a possible integer overflow for the `Size` calculation, incase `_Length - BaseVa` is large enought.

2. `MmInitializeMdl` have a possible type confusion.  if `_Length == -1` (signed int), it gets converted to `ULONG`, yields high value for `ByteCount`. 

3. `TransferMdl` is attacker - controlled data. Specifically, `TransferMdl->ByteCount` is fully controlled.

4. Heap buffer overflow due to under-allocation:

```c
UndoMdl = SkAllocatePool(NonPagedPoolNx, TransferMdl->ByteCount, 'ldmM');
...
MmInitializeMdl(UndoMdl, (PVOID)OriginalUndoMdl->ByteOffset, OriginalUndoMdl->ByteCount);
```

The macro `MmInitializeMdl` implicitly assumes the MDL was allocated with enough space, hence *at least sizeof(MDL) bytes*. 

However, the attacker may set `TransferMdl->ByteCount < sizeof(MDL)` (for example, 0), which will result with heap overflow by the macro.

### Patch

A simple a check for the above criteria was added.


## CVE-2019-7287 - Apple XNU kexts

### Code 

```c
//ACID: struct_in
IOReturn
ProvInfoIOKitUserClient::ucEncryptSUInfo(char* struct_in,
                                         char* struct_out){
  memmove(&struct_out[4],
          &struct_in[4],
          *(uint32_t*)&struct_in[0x7d4]);

// [...]
```

### Code Review

1. There is an obvious heap overflow: `struct_in` is fully controlled by the attacker (userspace), without any sanity checks. 

Therefore, it is possible to set the size of the `memmove`, aka `struct_in[0x7d4]` to overflow the `struct_out` heap address. 

### Patch

Added a sanity check for the provided size, prior to the `memmove` call. 


## CVE-2020-11901 - Part of Ripple20 

This is actually 4 vulnerabilities. We will focus only on the first one. 

Heap overflow within TCP/IP stack, for parsing received DNS packets. 

DNS protocol formats long hostname strings by breaking it into labels - each label is prefixed by its length byte. 
Multiple labels are supported, and separated by "." .

The end of the hostname string is when a `length == 0` is found for a label. 

Max supported label length is 63 bytes, and the max hostname length 255 bytes. 

For example, `www.google.com -> 3www6google3com0` .

Moreover, DNS supports `message compression`, meaning replacement of label / domain name by a pointer to a prior occurance of the same name. 

Compression pointer takes 2 bytes - and always starts with two `1` bits.

The first byte is reserved as an identification for compression label, hence a maximum length of 63 bytes. 

The second byte is the actual offset. 

### Code

```c
//ACID: RDLENGTH, resourceRecordAfterNamePtr, dnsHeaderPtr
if (RDLENGTH <= remaining_size) {
	/* compute the next resource record pointer based on the RDLENGTH */
	labelEndPtr = resourceRecordAfterNamePtr + 10 + RDLENGTH;
	/* type: MX */
	if (cacheEntryQueryType == DNS_TYPE_MX && rrtype == DNS_TYPE_MX) {
		addr_info = tfDnsAllocAddrInfo();
		if (addr_info != NULL && RDLENGTH >= 2) {
			/* copy preference value of MX record */
			memcpy(&addr_info->ai_mxpref,resourceRecordAfterNamePtr + 10, 2);
			/* compute the length of the MX hostname */
			labelLength = tfDnsExpLabelLength(resourceRecordAfterNamePtr + 0xc, dnsHeaderPtr, labelEndPtr);
			addr_info->ai_mxhostname = NULL;
			if (labelLength != 0) {
				/* allocate buffer for the expanded name */
				asciiPtr = tfGetRawBuffer((uint)labelLength);
				addr_info->ai_mxhostname = asciiPtr;
				if (asciiPtr != NULL) {
					/* copy MX hostname to `asciiPtr` as ASCII */
					tfDnsLabelToAscii(resourceRecordAfterNamePtr + 0xc, asciiPtr, dnsHeaderPtr, 1, 0);
					/* ... */
				}
				/* ... */
			}
			/* ... */
		}
	/* ... */
	}
}

tt16Bit tfDnsExpLabelLength(tt8BitPtr labelPtr, tt8BitPtr pktDataPtr, tt8BitPtr labelEndPtr){
	tt8Bit currLabelLength;
	tt16Bit i = 0, totalLength = 0;
	tt8BitPtr newLabelPtr;

	while (&labelPtr[i] < labelEndPtr && labelPtr[i] != 0) {
		currLabelLength = labelPtr[i];
		if ((currLabelLength & 0xc0) == 0) {
			totalLength += currLabelLength + 1;
			i += currLabelLength + 1;
		} else {
			if (&labelPtr[i+1] < labelEndPtr) {
				newLabelPtr = pktDataPtr + (((currLabelLength & 0x3f) << 8) | labelPtr[i+1]);
				if (newLabelPtr < labelPtr) {
					labelPtr = newLabelPtr;
					i = 0;
					continue;
				}
			}
		return 0;
		}
	}
	return totalLength;
}
```

### Code Review

1. `labelEndPtr` is controlled by the attacker, without any sanity checks for `RDLENGTH`. 

2. Attacker can increase `labelLength` using a bug within `tfDnsExpLabelLength`:
The loop continues as long as (1) `labelEndPtr` is larger than `labelPtr[i]` and (2) `labelPtr[i] != 0`.

Since we control `labelEndPtr` via `RDLENGTH`, (1) is resolved easily. 
Moreover - note we fully control the packet's data, meaning `resourceRecordAfterNamePtr`. 
In that case, we can change the terminating `\x00` byte into some positive integer, yielding a continuation of the loop, and larger result of `totalLength`. 

We can also do the opposite - and cause extremely low value of `totalLength`, by simply setting the `labelEndPtr` to extremely low value. 


3. Heap buffer overflow:

```c
	asciiPtr = tfGetRawBuffer((uint)labelLength);
	addr_info->ai_mxhostname = asciiPtr;
	if (asciiPtr != NULL) {
		/* copy MX hostname to `asciiPtr` as ASCII */
		tfDnsLabelToAscii(resourceRecordAfterNamePtr + 0xc, asciiPtr, dnsHeaderPtr, 1, 0);
```

As said, `labelLength` is controlled. 

An under-allocation of `asciiPtr` would be performed, and the last copy call will overflow the heap address of `asciiPtr`.

### Patch

No patch released. 


## CVE-2020-25111 - Part of Amnesia:33

### Code
