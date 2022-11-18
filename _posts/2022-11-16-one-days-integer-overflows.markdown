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

```c
////ACID: param_1
void FUN_00677d70(void **param_1, int param_2, int param_3, int param_4, int param_5 ,uint *param_6)
{
  int header_length;
  size_t _Size;
  int iVar1;
  int iVar2;
  int receiver_length;
  uint sender_length;
  /* Omitted code  */
  void *blkDrvPDUdata;
  /* Omitted code */
  iVar2 = *(int *)(param_2 + 0x128) +  DAT_007a3534;
  if (iVar2 < 0xf) {
     /* Omitted code */
    blkDrvPDUdata = *param_1;
    header_length = (*(byte *)((int)blkDrvPDUdata + 1) & 7) * 2;
    sender_length = *(byte *)((int)blkDrvPDUdata + 5) & 0xf;
    receiver_length = (int)(uint)*(byte *)((int)blkDrvPDUdata + 5) >> 4;
    pvVar3 = (void *)(sender_length + receiver_length + header_length);
    local_20c = header_length;
    if (pvVar3 < param_1[1] || pvVar3 == param_1[1]) {
      pvVar3 = *param_1;
      if ((*(byte *)((int)blkDrvPDUdata + 2) & 0x10) == 0) {
        *param_6 = header_length + (sender_length + receiver_length) * 2;
        if ((*param_6 & 3) != 0) {
          *param_6 = *param_6 + 2;
        }
        _Size = (int)param_1[1] - *param_6;

        /* Omitted  code*/
        if ((local_220 < 0x10) && (local_244 < 0x10)) {      
          /* Omitted  Code*/              
          if (local_20c + _Size_00 + iVar1 + local_214 + _Size < 0x201) {
            memcpy(local_208 + local_214 + iVar1 + _Size_00 + local_20c,
                   (void *)((int)*param_1 + *param_6), _Size );
            param_1[1] = (void *)(local_20c + _Size_00 + iVar1 + local_214 + _Size);
            memcpy(*param_1,local_208,(size_t)param_1[1]);
            *(int *)(param_5 + 0xc) = (int)*param_1 + local_20c;
            *(int *)(param_4 + 0xc) = *(int *)(param_5 + 0xc) + *(int *)(param_5 + 8) * 2;
            *param_6 = local_20c + _Size_00 + iVar1;
            if ((*param_6 & 3) != 0) {
              *param_6 = *param_6 + 2;
            }
          }
        }
      }
    }
  }
  FUN_006ce8f9();
  return;
}
```

### Code Review

1. `receiver_length` and `header_length` defined as int, not uint

2. `_Size` is controlled by user input

3. Stack buffer overflow to local buffer `local_208`, and heap buffer overflow for `param_1`:

```c
 if (local_20c + _Size_00 + iVar1 + local_214 + _Size < 0x201) {
            memcpy(local_208 + local_214 + iVar1 + _Size_00 + local_20c,
                   (void *)((int)*param_1 + *param_6), _Size );
            param_1[1] = (void *)(local_20c + _Size_00 + iVar1 + local_214 + _Size);
            memcpy(*param_1,local_208,(size_t)param_1[1]);
```

Despite the check for no overflow of 0x201 bytes, there is a possible wrap around.

For example, if `_Size = 0xffffffff`, addition of the other variables will lead to wrap around, to some low positive size.

This positive size can pass the check, hence proceeding to copy `_Size` bytes towards the local buffer, yielding stack buffer overflow.

Another possibility is to overflow the heap, via `param_1` overflow, as we fully control the content of `local_208` buffer.

`param_1[1]` can be set to some high value, while bypassing the check due to wrap around.

4. Note: both `sender_length` and `receiver_length` are actually bounded, due to the bits manipulations being made.
The `header_length` is unlimited tho. 

### Patch

No released patch. 


## CVE-2019-3568 - Facebook app RTCP

RTCP stands for the RTP control protocol. 
Enables VOIP capability, for example for WhatsApp. 

## CVE-2019-14192 - u-boot NFS

Used on embedded systems, to load a full OS (typically linux). 
It supports fetching the OS from the network, via NFS. 

### Code

```c
////ACID: in_packet
void net_process_received_packet(uchar *in_packet, int len)
{
	struct ethernet_hdr *et;
	struct ip_udp_hdr *ip;
	struct in_addr dst_ip;
	struct in_addr src_ip;
	int eth_proto;
	// ...
	ip = (struct ip_udp_hdr *)(in_packet + E802_HDR_SIZE);
	// ...
	switch (eth_proto) {
	// ...
	case PROT_IP:
		debug_cond(DEBUG_NET_PKT, "Got IP\n");
		/* Before we start poking the header, make sure it is there */
		if (len < IP_UDP_HDR_SIZE) {
			debug("len bad %d < %lu\n", len,
			      (ulong)IP_UDP_HDR_SIZE);
			return;
		}
		/* Check the packet length */
		if (len < ntohs(ip->ip_len)) {
			debug("len bad %d < %d\n", len, ntohs(ip->ip_len));
			return;
		}
		len = ntohs(ip->ip_len);
		// ...
		ip = net_defragment(ip, &len);
		if (!ip)
			return;
		// ...
		if (ip->ip_p == IPPROTO_ICMP) {
			receive_icmp(ip, len, src_ip, et);
			return;
		} else if (ip->ip_p != IPPROTO_UDP) {	/* Only UDP packets */
			return;
		}

		// ...
#if defined(CONFIG_NETCONSOLE) && !defined(CONFIG_SPL_BUILD)
		nc_input_packet((uchar *)ip + IP_UDP_HDR_SIZE,
				src_ip,
				ntohs(ip->udp_dst),
				ntohs(ip->udp_src),
				ntohs(ip->udp_len) - UDP_HDR_SIZE);
#endif
		/*
		 * IP header OK.  Pass the packet to the current handler.
		 */
		(*udp_packet_handler)((uchar *)ip + IP_UDP_HDR_SIZE,
				      ntohs(ip->udp_dst),
				      src_ip,
				      ntohs(ip->udp_src),
				      ntohs(ip->udp_len) - UDP_HDR_SIZE);
		break;
		// ...
	}
}
```

### Code Review

1. The `ip` packet content is controlled by the user.

2. There is an integer underflow on the calculation of the udp header length:

```c
ntohs(ip->udp_len) - UDP_HDR_SIZE)
```

User can set `ip->udp_len` to some low value, resulting with a negative size, hence large udp packet size.

### Patch

Checks for `ip->udp_len` were added: both lower and upper bounds. 


## CVE-2020-11901 - Part of Ripple20

### Code
