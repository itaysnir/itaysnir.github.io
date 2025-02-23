---
layout: post
title:  "1-Day Research - Integer Overflows"
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

### Code

```c
////ACID: echo
static int pico_icmp6_send_echoreply(struct pico_frame *echo)
{
    struct pico_frame *reply = NULL;
    struct pico_icmp6_hdr *ehdr = NULL, *rhdr = NULL;
    struct pico_ip6 src;
    struct pico_ip6 dst;

    reply = pico_proto_ipv6.alloc(&pico_proto_ipv6, echo->dev, (uint16_t)(echo->transport_len));
    if (!reply) {
        pico_err = PICO_ERR_ENOMEM;
        return -1;
    }

    echo->payload = echo->transport_hdr + PICO_ICMP6HDR_ECHO_REQUEST_SIZE;
    reply->payload = reply->transport_hdr + PICO_ICMP6HDR_ECHO_REQUEST_SIZE;
    reply->payload_len = echo->transport_len;

    ehdr = (struct pico_icmp6_hdr *)echo->transport_hdr;
    rhdr = (struct pico_icmp6_hdr *)reply->transport_hdr;
    rhdr->type = PICO_ICMP6_ECHO_REPLY;
    rhdr->code = 0;
    rhdr->msg.info.echo_reply.id = ehdr->msg.info.echo_reply.id;
    rhdr->msg.info.echo_reply.seq = ehdr->msg.info.echo_request.seq;
    memcpy(reply->payload, echo->payload, (uint32_t)(echo->transport_len - PICO_ICMP6HDR_ECHO_REQUEST_SIZE));
    rhdr->crc = 0;
    rhdr->crc = short_be(pico_icmp6_checksum(reply));
    /* Get destination and source swapped */
    memcpy(dst.addr, ((struct pico_ipv6_hdr *)echo->net_hdr)->src.addr, PICO_SIZE_IP6);
    memcpy(src.addr, ((struct pico_ipv6_hdr *)echo->net_hdr)->dst.addr, PICO_SIZE_IP6);
    pico_ipv6_frame_push(reply, &src, &dst, PICO_PROTO_ICMP6, 0);
    return 0;
}

/* allocates an IPv6 packet without extension headers. If extension headers are needed,
 * include the len of the extension headers in the size parameter. Once a frame acquired
 * increment net_len and transport_hdr with the len of the extension headers, decrement
 * transport_len with this value.
 */
static struct pico_frame *pico_ipv6_alloc(struct pico_protocol *self, struct pico_device *dev, uint16_t size)
{
    struct pico_frame *f = NULL;

    IGNORE_PARAMETER(self);

    if (0) {}
#ifdef PICO_SUPPORT_6LOWPAN
    else if (PICO_DEV_IS_6LOWPAN(dev)) {
        f = pico_proto_6lowpan_ll.alloc(&pico_proto_6lowpan_ll, dev, (uint16_t)(size + PICO_SIZE_IP6HDR));
    }
#endif
    else {
#ifdef PICO_SUPPORT_ETH
        f = pico_proto_ethernet.alloc(&pico_proto_ethernet, dev, (uint16_t)(size + PICO_SIZE_IP6HDR));
#else
        f = pico_frame_alloc(size + PICO_SIZE_IP6HDR + PICO_SIZE_ETHHDR);
#endif
    }

    if (!f)
        return NULL;

    f->net_len = PICO_SIZE_IP6HDR;
    f->transport_hdr = f->net_hdr + PICO_SIZE_IP6HDR;
    f->transport_len = (uint16_t)size;

    /* Datalink size is accounted for in pico_datalink_send (link layer) */
    f->len =  (uint32_t)(size + PICO_SIZE_IP6HDR);

    return f;
}
```

### Code Review

1. Integer overflows at `pico_ipv6_alloc`, for all of the `.alloc` calculations. 

This may result with an under-allocation for `f`, hence yields an OOB write for the following attributes:

```c
f->net_len = PICO_SIZE_IP6HDR;
f->transport_hdr = f->net_hdr + PICO_SIZE_IP6HDR;
f->transport_len = (uint16_t)size;

/* Datalink size is accounted for in pico_datalink_send (link layer) */
f->len =  (uint32_t)(size + PICO_SIZE_IP6HDR);
```

Another integer overflow resides at the above line, adjusting the `len` field.

2. Integer overflow that leads to heap buffer overflow:

```c
memcpy(reply->payload, echo->payload, (uint32_t)(echo->transport_len - PICO_ICMP6HDR_ECHO_REQUEST_SIZE));
```

### Patch

Added a check for `echo->transport_len` value. 


## CVE-2021-30860 - FORCEDENTRY (NSO IPhone Vuln)

```c
enum JBIG2SegmentType
{
    jbig2SegBitmap,
    jbig2SegSymbolDict,
    jbig2SegPatternDict,
    jbig2SegCodeTable
};

////ACID: refSegs, nRefSegs
void JBIG2Stream::readTextRegionSeg(unsigned int segNum, bool imm, bool lossless, unsigned int length, unsigned int *refSegs, unsigned int nRefSegs)
{
    JBIG2Segment *seg;
    std::vector codeTables;
    JBIG2SymbolDict *symbolDict;
    JBIG2Bitmap **syms;
    unsigned int huff;
    unsigned int numSyms, symCodeLen;
    unsigned int i, k, kk;

    // ...

    // get symbol dictionaries and tables
    numSyms = 0;
    for (i = 0; i < nRefSegs; ++i) {
        if ((seg = findSegment(refSegs[i]))) {
            if (seg->getType() == jbig2SegSymbolDict) {
                numSyms += ((JBIG2SymbolDict *)seg)->getSize();
            } else if (seg->getType() == jbig2SegCodeTable) {
                codeTables.push_back(seg);
            }
        } else {
            error(errSyntaxError, curStr->getPos(), "Invalid segment reference in JBIG2 text region");
            return;
        }
    }

    // ...

    // get the symbol bitmaps
    syms = (JBIG2Bitmap **)gmallocn(numSyms, sizeof(JBIG2Bitmap *));
    if (numSyms > 0 && !syms) {
        return;
    }
    kk = 0;
    for (i = 0; i < nRefSegs; ++i) {
        if ((seg = findSegment(refSegs[i]))) {
            if (seg->getType() == jbig2SegSymbolDict) {
                symbolDict = (JBIG2SymbolDict *)seg;
                for (k = 0; k < symbolDict->getSize(); ++k) {
                    syms[kk++] = symbolDict->getBitmap(k);
                }
            }
        }
    }
```

### Code Review

1. Since `nRefSegs` is controlled, as well as `refSegs` is controlled, it is possible to forge an unbounded number of segments.

This causes unbounded number of additions of the segment's size to `numSyms`:

```c
numSyms += ((JBIG2SymbolDict *)seg)->getSize();
```

Which eaily causes an integer overflow. 

2. The integer overflow causes an heap under-allocation:

```c
syms = (JBIG2Bitmap **)gmallocn(numSyms, sizeof(JBIG2Bitmap *));
```

3. `syms` under-allocation results with an heap OOB write primitive, of controlled input:

```c
syms[kk++] = symbolDict->getBitmap(k);
```

### Patch

No released patch.

## CVE-2021-22636 - TI Memory Allocator

One of BadAlloc family vulns.


### Code

```c
int16_t _BundleCmdSignatureFile_Parse(
    OtaArchive_BundleCmdTable_t *pBundleCmdTable,
    uint8_t *pRecvBuf,    //XENO: ACID: TAR file received over network
    int16_t RecvBufLen,   //XENO: SACI: Size of TAR file received over network
    int16_t *ProcessedSize,
    uint32_t SigFileSize, //XENO: ACID: Size from TAR file headers
    uint8_t *pDigest)
{
    int16_t retVal = 0;
    char *  pSig = NULL;

    /* Get the entire signature file */
    retVal = GetEntireFile(pRecvBuf, RecvBufLen, ProcessedSize, SigFileSize,
                           &pSig);
    if(retVal < 0)
    {
        return(retVal);
    }
    if(retVal == GET_ENTIRE_FILE_CONTINUE)
    {
        return(ARCHIVE_STATUS_BUNDLE_CMD_SIGNATURE_CONTINUE);
    }

    /* Verify the signature using ECDSA */
    retVal = verifySignature(pSig, SigFileSize, pDigest);
    if(retVal < 0)
    {
        _SlOtaLibTrace((
                           "[_BundleCmdSignatureFile_Parse] "
                           "signature verification failed!\r\n"));
        return(retVal);
    }

    pBundleCmdTable->VerifiedSignature = 1;

    return(ARCHIVE_STATUS_BUNDLE_CMD_SIGNATURE_DOWNLOAD_DONE);
}
int16_t GetEntireFile(uint8_t *pRecvBuf,
                      int16_t RecvBufLen,
                      int16_t *ProcessedSize,
                      uint32_t FileSize,
                      char **pFile)
{
    int16_t copyLen = 0;
    static bool firstRun = TRUE;
    static int16_t TotalRecvBufLen = 0;

    if(firstRun)
    {
        TotalRecvBufLen = RecvBufLen;
        firstRun = FALSE;
        if(TotalRecvBufLen < FileSize)
        {
            /* Didn't receive the entire file in the first run. */
            /* Allocate a buffer in the size of the entire file and fill
                it in each round. */
            pTempBuf = (char*)malloc(FileSize + 1);
            if(pTempBuf == NULL)
            {
                /* Allocation failed, return error. */
                return(-1);
            }
            memcpy(pTempBuf, (char *)pRecvBuf, RecvBufLen);
            *ProcessedSize = RecvBufLen;

            /* didn't receive the entire file, try in the next packet */
            return(GET_ENTIRE_FILE_CONTINUE);
        }
        else
        {
            /* Received the entire file in the first run. */
            /* No additional memory allocation is needed. */
            *ProcessedSize = FileSize;
            *pFile = (char *)pRecvBuf;
        }
    }
    else
    {
        /* Avoid exceeding buffer size (FileSize + 1) */
        if(RecvBufLen > ((FileSize + 1) - TotalRecvBufLen))
        {
            copyLen = ((FileSize + 1) - TotalRecvBufLen);
        }
        else
        {
            copyLen = RecvBufLen;
        }

        /* Copy the received buffer from where we stopped the previous copy */
        memcpy(&(pTempBuf[TotalRecvBufLen]), (char *)pRecvBuf, copyLen);

        *ProcessedSize = copyLen;
        TotalRecvBufLen += copyLen;

        if(TotalRecvBufLen < FileSize)
        {
            /* didn't receive the entire file, try in the next packet */
            return(GET_ENTIRE_FILE_CONTINUE);
        }

        /* At this point we have the whole file */
        *pFile = (char *)pTempBuf;
    }

    /* Set static variables to initial values to allow retry in 
    case of a warning during the OTA process */
    firstRun = TRUE;
    TotalRecvBufLen = 0;

    return(GET_ENTIRE_FILE_DONE);
}
void ATTRIBUTE *malloc(size_t size)
{
    Header *packet;

    if (size == 0) {
        errno = EINVAL;
        return (NULL);
    }

    packet = (Header *)pvPortMalloc(size + sizeof(Header));

    if (packet == NULL) {
        errno = ENOMEM;
        return (NULL);
    }

    packet->header.actualBuf = (void *)packet;
    packet->header.size = size + sizeof(Header);

    return (packet + 1);
}
```

### Code Review

1. This `malloc` implementation is pretty old, and contains no sanity checks for the input `size`.

It allocates memory for both data chunk, as well as the header metadata, `sizeof(Header)`.

This results with an integer overflow for the effective allocated memory size, issued by `pvPortMalloc()` (analogous to `__malloc_hook`).

2. The above integer overflow may be triggered at the following `malloc` call:

```c
pTempBuf = (char*)malloc(FileSize + 1);
if(pTempBuf == NULL)
{
    /* Allocation failed, return error. */
    return(-1);
}
memcpy(pTempBuf, (char *)pRecvBuf, RecvBufLen);
```

As `FileSize` is user-controlled.
Note that the extra integer overflow here isn't easily exploitable.

This `malloc` version does not support with `size=0` allocations. 

Therefore, passing `FileSize = 0xffffffff` would result with `malloc(0)`, which would fail to allocate the desired memory.

The trick is to send `size = 0xffffffff`, and exploit `malloc`'s integer overflow. 

3. This results with an under-allocation, leading to heap buffer overflow.

### Patch

`malloc` implementation was added an extra sanity check:

```c
allocSize = size + sizeof(Header);
if (allocSize < size)
	return NULL;
```

## Extra CVEs For Learning

```bash
CVE-2021-31956
CVE-2022-0185
CVE-2022-0545
CVE-2021-30883
CVE-2020-9852
CVE-2021-30717
CVE-2020-1350 "SIGRed" 
CVE-2022-24354
CVE-2020-16968
```

And [this][extra-cve]

## Safe Math Sanity Checks

### Anti Patterns

```c
if (a + b > c)  // a + b may wrap around. Also signess insanity checks.

if (a > c - b)  // c - b may underflow

if (a + b < a)  // signess may be problematic

```

### Compiler-Supported Safe Math

It is acctually not trivial at all, considering all possible scenarios. 

*Built-in compiler intrinsics* are here to help. 

For example (both for clang and gcc):

```c
__builtin_add_overflow()
__builtin_mul_overflow()
__builtin_uadd_overflow()
...
```

Trivial usage:

```c
unsigned int a = atoi(argv[1]);
unsigned int b = atoi(argv[2]);
unsigned int c; 
bool overflowed = false;

overflowed = __builtin_add_overflow(a, b, &c);
if (overflowed)
{
	printf("INTEGER OVF\n");
	return -1;
}
```

In a similar manner, the Windows kernel has the `ntintsafe.h` header. 

## UBSan for IOU

`-fsanitize=integer` adds runtime checks for "suspicious" integer behavior at runtime. 

Either by signed/unsigned overflows, shifts, divide by zero, truncation, implicit sign changes, etc. 

[extra-cve]: https://fredericb.info/2020/06/exynos-usbdl-unsigned-code-loader-for-exynos-bootrom.html#exynos-usbdl-unsigned-code-loader-for-exynos-bootrom
