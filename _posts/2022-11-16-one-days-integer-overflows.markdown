---
layout: post
title:  "One Days - Integer Overflows"
date:   2022-11-18 20:00:01 +0300
categories: jekyll update
---

**Contents**
* TOC
{:toc}
## Background

### Operators
Pretty obvious overflow for the regular math operators (+ , -, *).

```c
+ , - , * ,  ...
```

Note there are special operators, that might have unexpected behavior

```c
<< , >>  // What does it mean to shift by negative number? Compiler dependent 
%  // negative % positive = negative! positive % negative = positive
```

### Common Errors Examples

```c
// Can result with wrap-around of the allocated chunk size
void *dst = malloc(const_size + input1);
void *dst = malloc(input1 + input2);
void *dst = malloc(const_size * input1); 

memcpy(dst, src, input1); // Non-trivial overflow right here
```

*BadAlloc* Bugs - 

Allocators may not check for integer overflows themselves. \
By requesting X bytes, some allocators may actually request X + Y bytes (for bytes metadata). 

This may overflow, and lead to under-allocation. 

These tricks are very cool, and important to know. 

#### Malloc

By asking X bytes, usually on x86 `malloc` actually allocates `8 + X = SMALL` bytes. 

This can result with an heap overflow, caused by an integer wrap around!

#### Calloc 

Even worse - as it takes two arguments (`size` and `nmembers`), multiplies them, and calls `__malloc_hook`. 

## CVE-2020-0796 - SMBGhost

### Code

```c
////ACID: The date pointed to by request->pNetRawBuffer
signed __int64 __fastcall Srv2DecompressData(SRV2_WORKITEM *workitem)
{
    // declarations omitted
    ...
    request = workitem->psbhRequest;
    if ( request->dwMsgSize < 0x10 )
        return 0xC000090B;
    compressHeader = *(CompressionTransformHeader *)request->pNetRawBuffer;
    ...
   
    newHeader = SrvNetAllocateBuffer((unsigned int)(compressHeader.originalCompressedSegSize + compressHeader.offsetOrLength), 0);
    if ( !newHeader )
        return 0xC000009A;
   
    if ( SmbCompressionDecompress(
                compressHeader.compressionType,
                &workitem->psbhRequest->pNetRawBuffer[compressHeader.offsetOrLength + 16],
                workitem->psbhRequest->dwMsgSize - compressHeader.offsetOrLength - 16,
                &newHeader->pNetRawBuffer[compressHeader.offsetOrLength],
                compressHeader.OriginalCompressedSegSize,
                &finalDecompressedSize) < 0
            || finalDecompressedSize != compressHeader.originalCompressedSegSize) )
    {
        SrvNetFreeBuffer(newHeader);
        return 0xC000090B;
    }
    if ( compressHeader.offsetOrLength )
    {
        memmove(newHeader->pNetRawBuffer, workitem->psbhRequest->pNetRawBuffer + 16, compressHeader.offsetOrLength);
    }
    newHeader->dwMsgSize = compressHeader.OffsetOrLength + fianlDecompressedSize;
    Srv2ReplaceReceiveBuffer(workitem, newHeader);
    return 0;
}
```

### Code Review

1. `compressHeader` is fully attacker-controlled. 

There is a clear integer overflow here:

```c
newHeader = SrvNetAllocateBuffer((unsigned int)(compressHeader.originalCompressedSegSize + compressHeader.offsetOrLength), 0);
```

Resulting with an under-allocated heap buffer.

2. The resulting heap buffer overflow:

Both on `SmbCompressionDecompress` and:

```c
memmove(newHeader->pNetRawBuffer, workitem->psbhRequest->pNetRawBuffer + 16, compressHeader.offsetOrLength);
```

### Patch

No patch released.

## CVE-2019-5105

### Code
