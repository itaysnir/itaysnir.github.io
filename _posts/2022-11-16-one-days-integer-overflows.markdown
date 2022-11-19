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

These are actually 4 vulnerabilities. 
I will focus here on vulnerability #2 

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

1. Focusing on `tfDnsExpLabelLength`: we fully control `labelPtr` and `pktDatPtr` content, as well as the value of `labelEndPtr`. 

Therefore, by choosing a large value for `RDLENGTH` (depends on the value of `remaining_size`), or just not setting the `\x00` byte at the end of the label, the while loop won't stop. 

2. Integer overflows -

`currLabelLength` is defined as 8-bit variable, `totalLength` as 16-bit variable.
Therefore, it is not trivial at all to overflow `totalLength`, since there is a maximum length of DNS packet (1460 bytes!).  

```c
totalLength += currLabelLength + 1;
i += currLabelLength + 1;
```

My idea is abit tricky, and utilizes the compressed pointers mechanism. 

The following packet structure may cause `totalLength` to overflow:

We would insert large labels, and at the end a compressed pointer.
This compressed pointer would point backwards to the start of the label, at an offset of one (so there won't be any "infinite loop").

```c
size  label_content   backwards_pointer
\x3f  \x3f\x3f...     \xc0 \x0e 
```

The trick is that the backwards pointer actually self-references its own label, hence making a very large chunk. 

The vulnerability slides from blackhat explains the 2D matrix array layout more in-depth. 

This yields a low `totalLength` value, hence causing `tfGetRawBuffer` to underflow. 

### Patch

No released patch.


## CVE-2020-16225 - TPEditor

### Code

```c
////ACID: The data read from staFileHandler
FILE *staFileHandler; //File handler is valid and already points to 0x200 location 
                      //in .sta file being loaded.
size_t x;
size_t y;
size_t allocSize;
void *memoryAllocation;

fread(&x, 4, 1, staFileHandler);
fread(&y, 4, 1, staFileHandler);
allocSize = y - x;
memoryAllocation = VirtualAlloc(0, allocSize, 0x3000, 4);
fread(memoryAllocation+x, 1, allocSize, staFileHandler);
```

### Code Review

1. `allocSize` defined as an unsigned int, yet is the result of user-controlled numbers substraction.

Therefore, `allocSize` is fully controlled. 

However, note that both `VirtualAlloc` and `fread` treats it as a `size_t`, therefore it will allocate and copy the exact same amount of bytes, regardless of the overflow.

2. The cool trick here is the usage of the `x` variable.

There is an integer overflow within this calculation: 

```c
fread(memoryAllocation+x, 1, allocSize, staFileHandler);
```

Since `x` is user-controlled, user may enter arbitrary value, so the addition may wrap-around, hence allowing OOB write to even lower addresses. 

Another trick utilizes the fact that `VirtualAlloc` return value isn't checked.

The idea is to make the value of `allocSize` maximal (0xffffffff), so that `VirtualAlloc` call fails, and return a `NULL = 0`.

That way, the returned address isn't randomized, and `x` would simply determine the OOB address we would like to write to. 

Note that read of 0xffffffff bytes from file does not crash. 

### Patch 

No released patch.


## CVE-2020-17443 - Part of Amnesia:33


