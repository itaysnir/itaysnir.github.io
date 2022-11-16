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


## CVE-2019-7287

