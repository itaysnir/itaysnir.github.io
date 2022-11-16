---
layout: post
title:  "One Days - Heap Buffer Overflows"
date:   2022-11-15 19:59:43 +0300
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

These are actually 4 vulnerabilities. I will focus only on one. 

Heap overflow within TCP/IP stack, for parsing received DNS packets. 

DNS protocol formats long hostname strings by breaking it into labels - each label is prefixed by its length byte. 
Multiple labels are supported, and separated by "." .

The end of the hostname string is when a `length == 0` is found for a label. 

Max supported label length is 63 bytes, and the max hostname length 255 bytes. 

For example, `www.google.com -> 3www6google3com0` .

Moreover, DNS supports *message compression*, meaning replacement of label / domain name by a pointer to a prior occurance of the same name. 

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

Yet another TCP/IP stack DNS vulnerability. 

### Code

```c
////ACID: cp
static uint16_t ScanName(uint8_t * cp, uint8_t ** npp){
	uint8_t len;
	uint16_t rc;
	uint8_t *np;

	if(*npp){
		free(*npp);
		*npp = 0;
	}

	if((*cp & 0xC0) == 0xC0)
		return 2;

	rc = strlen((char *) cp) + 1;
	np = *npp = malloc(rc);
	len = *cp++;
	while(len){
		while (len--)
			*npp++ = *cp++;
		if((len = *cp++) != 0)
			*np++ = '.';
	}
	*np = 0;

	return rc;
}
```

### Code Review

1. `cp` points towards the compression pointer of the encoded DNS hostname string within the packet. 

2. The name pointers (`np, npp`) are malloced by a size, `rc`, determined by the given input. 
This size calculation example:

`3www6google3com0` is interpreted as `1+3+1+6+1+3 + 1` bytes, yielding 16 bytes, for 15 bytes name `www.google.com\x00`. 

3. Heap buffer overflow:

Note the while loop actually continues according to the written `len` byte within the packet. 
Therefore, since we fully control `cp`, it is possible to insert a packet with mismatching `len` byte and string;

For example, `\x30AA\x00` interpreted as a loop of 0x30 elements, while allocating only `3 + 1 = 4` bytes. 

This results with an under-allocation of the name buffer.

### Patch

No patch released.


## CVE-2020-27009 - Part of NAME:WRECK

Yet another DNS vuln. 

### Code

```c
//// No src was given for GET16() but we will assume it behaves as below:
#define GET16(base, offset) *(unsigned short *)((void *)(base) + offset)

////ACID: pkt
STATUS DNS_Extract_Data (DNS_PKT_HEADER *pkt, CHAR *data, UNSIGNED *ttl, INT type){
	DNS_RR			*pr_ptr;
	INT			name_size, n_answers, rcode;
	UINT16			length;
	CHAR			*p_ptr, *name;

	n_answers = GET16(pkt, DNS_ANCOUNT_OFFSET);
	// [...]
	/* If there is at least one reasonable answer and this is a response, process it */
	if ((n_answers > 0) && (GET16(pkt, DNS_FLAGS_OFFSET) & DNS_QR)) {
		/* Point to where the question starts.*/
		p_ptr = (CHAR *)(pkt + 1);
		/* Allocate a block of memory to put the name in */
		if (NU_Allocate_Memory (&System_Memory, (VOID **)&name,
							DNS_MAX_NAME_SIZE,
							NU_NO_SUSPEND) != NU_SUCCESS) {
			return (NU_NO_MEMORY);
		}
	
		/* Extract the name. */
		name_size = DNS_Unpack_Domain_Name (name, p_ptr, (CHAR *)pkt);

		/*	Move the pointer past the name QTYPE and QCLASS to point at the
			answer section of the response. */
		p_ptr += name_size + 4;

		/*	At this point, there may be several answers. We will take the first
			answer section of the response. */
		while ((n_answers--) > 0){
			/* Extract the name from the answer. */
			name_size = DNS_Unpack_Domain_Name (name, p_ptr, (CHAR *)pkt);
			/* Move the pointer past the name. */
			p_ptr += name_size;
			/* Point to the resource record. */
			rr_ptr = (DNS_RR *)p_ptr;
			// [...]
			/* Copy the length of this answer. */
			length = GET16(rr_ptr, DNS_RDLENGTH_OFFSET);
			// [...]
		}
		// [...]
	}
	// [...]
}

////ACID: src
INT DNS_Unpack_Domain_Name(CHAR * dst, CHAR *src, CHAR *buf_begin) {
	INT16		size;
	INT		i, retval = 0;
	CHAR		*savesrc;
	
	savesrc = src;
	
	while (*src){
		size = *src;

		while ((size & 0xC0) == 0xC0){
			if (!retval)
			{
				retval = src - savesrc + 2;
			}
			src++;
			src = &buf_begin[(size & 0x3f) * 256 + *src];
			size = *src;
		}
		src++;

		for (i=0; i < (size & 0x3f); i++){
			*dst++ = *src++;
		}
		*dst++ = '.';
	}

	*(--dst) = 0;
	src++;

	if (!retval) {
		retval = src - savesrc;
	}
	
	return (retval);
}
```

### Code Review

1. `name` is allocated by a static size, `DNS_MAX_NAME_SIZE` (255). 

2. Heap buffer overflow within `DNS_Unpack_Domain_Name`:

The effective size is determined by the encoded sent packet. 

Therefore, if the crafted hostname is larger than `DNS_MAX_NAME_SIZE` (either regular / compressed size), an overflow would occur.

Example: let us assume the domain starts at offset 0x0c. 

`\x3www\x6google\x3com\xc0\x0c\xc0\x0c...`

The resulting hostname string is larger than the maximum value (255).

Note: the code does sanitize corretly the size of a single label (`i < (size & 0x3f)`).

However, since we can easily cascade labels, the maximum 255 value is easly overflowed. 

### Patch

No released patch.

## CVE-2021-21555 - Dell UEFI

UEFI supports *non-volatile-variables*, which are stored on SPI flash chip. 
These can even be used by an OS (usually to configure FW options).

For example, stating the next OS image to boot from. 

Some NV variables are ment only for FW usage, not the OS.

However, most FW developers enables NV-vars writes via kernel permissions. 

Therefore, if attacker gained kernel privileges, it may actually tweak the FW configuration, using the kernel<->FW interface of NV variables. 

The SPI memory is actually splitted to regions. Some of these regions are immutable, hence using an integrity check at boot time, while some of them are "naturally changing", and not being part of any kind of integrity check. 

### Code

```c
Tries = 3;
DataSize = 0; 
...
  do
  {
   Status = gRT->GetVariable(L"AepErrorLog", 
          &VendorGuid, 
          0, 
          &DataSize, 
          mEraseRecordShare);
    --Tries;
  }
  while ( Status < 0 && Tries );
...
```

### Code Review

1. We control NVRAM variables (assuming kernel priviledges), and `mEraseRecordShare` is 964 bytes long buffer. 

2. After a single call for `GetVariable`, `DataSize` is set to the size of the data stored within the buffer. 

Note: in case the buffer is too small to hold the content of the variable, `DataSize` is set to the required buffer size.

3. Heap overflow:
- We may set the variable of `AepErrorLog` to some large buffer, above 964 bytes (lets say, 0x1000). 

- The first try fill fail (as `DataSize` was initialized to 0), and store this large value (0x1000) within DataSize. 

- On the second iteration, it will copy 0x1000 bytes to a heap buffer of 964 bytes. 

### Patch

No released patch.

## CVE-2021-42739 - Linux Kernel CA_SEND_MSG ioctl

There is an optional kernel module (fdtv) that exposes ioctrl interface for controlling firewire digital TV.

User can send arbitrary input data towards the kernel, via the ioctl interface.

### Code

```c
struct ca_msg {
	unsigned int index;
	unsigned int type;
	unsigned int length;
	unsigned char msg[256];
};

////ACID: arg
static int fdtv_ca_pmt(struct firedtv *fdtv, void *arg)
{
	struct ca_msg *msg = arg;
	int data_pos;
	int data_length;
	int i;

	data_pos = 4;
	if (msg->msg[3] & 0x80) {
		data_length = 0;
		for (i = 0; i < (msg->msg[3] & 0x7f); i++)
			data_length = (data_length << 8) + msg->msg[data_pos++];
	} else {
		data_length = msg->msg[3];
	}

	return avc_ca_pmt(fdtv, &msg->msg[data_pos], data_length);
}

struct avc_command_frame {
	u8 ctype;
	u8 subunit;
	u8 opcode;
	u8 operand[509];
};

int avc_ca_pmt(struct firedtv *fdtv, char *msg, int length)
{
	struct avc_command_frame *c = (void *)fdtv->avc_data;
	struct avc_response_frame *r = (void *)fdtv->avc_data;
	int list_management;
	int program_info_length;
	int pmt_cmd_id;
	int read_pos;
	int write_pos;
	int es_info_length;
	int crc32_csum;
	int ret;

	if (unlikely(avc_debug & AVC_DEBUG_APPLICATION_PMT))
		debug_pmt(msg, length);

	mutex_lock(&fdtv->avc_mutex);

	c->ctype   = AVC_CTYPE_CONTROL;
	c->subunit = AVC_SUBUNIT_TYPE_TUNER | fdtv->subunit;
	c->opcode  = AVC_OPCODE_VENDOR;

	if (msg[0] != EN50221_LIST_MANAGEMENT_ONLY) {
		dev_info(fdtv->device, "forcing list_management to ONLY\n");
		msg[0] = EN50221_LIST_MANAGEMENT_ONLY;
	}
	/* We take the cmd_id from the programme level only! */
	list_management = msg[0];
	program_info_length = ((msg[4] & 0x0f) << 8) + msg[5];
	if (program_info_length > 0)
		program_info_length--; /* Remove pmt_cmd_id */
	pmt_cmd_id = msg[6];

	c->operand[0] = SFE_VENDOR_DE_COMPANYID_0;
	c->operand[1] = SFE_VENDOR_DE_COMPANYID_1;
	c->operand[2] = SFE_VENDOR_DE_COMPANYID_2;
	c->operand[3] = SFE_VENDOR_OPCODE_HOST2CA;
	c->operand[4] = 0; /* slot */
	c->operand[5] = SFE_VENDOR_TAG_CA_PMT; /* ca tag */
	c->operand[6] = 0; /* more/last */
	/* Use three bytes for length field in case length > 127 */
	c->operand[10] = list_management;
	c->operand[11] = 0x01; /* pmt_cmd=OK_descramble */

	/* TS program map table */

	c->operand[12] = 0x02; /* Table id=2 */
	c->operand[13] = 0x80; /* Section syntax + length */

	c->operand[15] = msg[1]; /* Program number */
	c->operand[16] = msg[2];
	c->operand[17] = msg[3]; /* Version number and current/next */
	c->operand[18] = 0x00; /* Section number=0 */
	c->operand[19] = 0x00; /* Last section number=0 */
	c->operand[20] = 0x1f; /* PCR_PID=1FFF */
	c->operand[21] = 0xff;
	c->operand[22] = (program_info_length >> 8); /* Program info length */
	c->operand[23] = (program_info_length & 0xff);

	/* CA descriptors at programme level */
	read_pos = 6;
	write_pos = 24;
	if (program_info_length > 0) {
		pmt_cmd_id = msg[read_pos++];
		if (pmt_cmd_id != 1 && pmt_cmd_id != 4)
			dev_err(fdtv->device,
				"invalid pmt_cmd_id %d\n", pmt_cmd_id);
		if (program_info_length > sizeof(c->operand) - 4 - write_pos) {
			ret = -EINVAL;
			goto out;
		}

		memcpy(&c->operand[write_pos], &msg[read_pos],
		       program_info_length);
		read_pos += program_info_length;
		write_pos += program_info_length;
	}
	while (read_pos < length) {
		c->operand[write_pos++] = msg[read_pos++];
		c->operand[write_pos++] = msg[read_pos++];
		c->operand[write_pos++] = msg[read_pos++];
		es_info_length =
			((msg[read_pos] & 0x0f) << 8) + msg[read_pos + 1];
		read_pos += 2;
		if (es_info_length > 0)
			es_info_length--; /* Remove pmt_cmd_id */
		c->operand[write_pos++] = es_info_length >> 8;
		c->operand[write_pos++] = es_info_length & 0xff;
		if (es_info_length > 0) {
			pmt_cmd_id = msg[read_pos++];
			if (pmt_cmd_id != 1 && pmt_cmd_id != 4)
				dev_err(fdtv->device, "invalid pmt_cmd_id %d at stream level\n",
					pmt_cmd_id);

			if (es_info_length > sizeof(c->operand) - 4 -
					     write_pos) {
				ret = -EINVAL;
				goto out;
			}

			memcpy(&c->operand[write_pos], &msg[read_pos],
			       es_info_length);
			read_pos += es_info_length;
			write_pos += es_info_length;
		}
	}
	write_pos += 4; /* CRC */

	c->operand[7] = 0x82;
	c->operand[8] = (write_pos - 10) >> 8;
	c->operand[9] = (write_pos - 10) & 0xff;
	c->operand[14] = write_pos - 15;

	crc32_csum = crc32_be(0, &c->operand[10], c->operand[12] - 1);
	c->operand[write_pos - 4] = (crc32_csum >> 24) & 0xff;
	c->operand[write_pos - 3] = (crc32_csum >> 16) & 0xff;
	c->operand[write_pos - 2] = (crc32_csum >>  8) & 0xff;
	c->operand[write_pos - 1] = (crc32_csum >>  0) & 0xff;
	pad_operands(c, write_pos);

	fdtv->avc_data_length = ALIGN(3 + write_pos, 4);
	ret = avc_write(fdtv);
	if (ret < 0)
		goto out;

	if (r->response != AVC_RESPONSE_ACCEPTED) {
		dev_err(fdtv->device,
			"CA PMT failed with response 0x%x\n", r->response);
		ret = -EACCES;
	}
out:
	mutex_unlock(&fdtv->avc_mutex);

	return ret;
}
```

### Code Review

1. `fdtv_ca_pmt` initializes `data_length` as int, instead of uint. 

2. `fdtv_ca_pmt` have no overflow for `data_pos`, as it has a maximal value of `4 + 0x7f` , which is below 256. 

However, it supports multiple bytes presentation for `data_length`. It therefore enables full control over `data_length`, even setting it to some negative values. 

3. The following block seemed interesting:

```c
read_pos = 6;
write_pos = 24;
	if (program_info_length > 0) {
		pmt_cmd_id = msg[read_pos++];
		if (pmt_cmd_id != 1 && pmt_cmd_id != 4)
			dev_err(fdtv->device,
				"invalid pmt_cmd_id %d\n", pmt_cmd_id);
		if (program_info_length > sizeof(c->operand) - 4 - write_pos) {
			ret = -EINVAL;
			goto out;
		}

		memcpy(&c->operand[write_pos], &msg[read_pos],
		       program_info_length);
		read_pos += program_info_length;
		write_pos += program_info_length;
	}
```

`program_info_length` is fully controlled by the input. 
However, the `memcpy` exloit isn't trivial - as there is a check, asserting `program_info_length` does not exceeds a harsh limit, that is below the buffer `c->operand` size (509 bytes). 

Note - `program_info_length` is a signed integer. 
Meaning, we can set this to `-1`, the check would pass, and the `memcpy` would copy 0xfffffff bytes ...

Except it doesn't work, as there is a positive value of `program_info_length` check. 

However, note that `msg[]` buffer is defined as 256-bytes array, while the controlled copied length is up to `509 - 4 - 24` bytes.
This means we can leak data beyond `msg[]`, to be stored within  the `c->operand[]` buffer, possibly yields an info leak primitive.

That is an exactly *OOB read primitive*!

4. Heap buffer overflow:

```c
while (read_pos < length) {
		c->operand[write_pos++] = msg[read_pos++];
		c->operand[write_pos++] = msg[read_pos++];
		c->operand[write_pos++] = msg[read_pos++];
    ...
}
```

The `length` variable is fully controlled by the input, and so is the `msg` buffer.
However, `c->operand` is 509 fixed-size bytes array, which is easly overflowed within this snippet. 


5. An interesting `memcpy`:

```c
memcpy(&c->operand[write_pos], &msg[read_pos],
			       es_info_length);
```

The maximal value of `es_info_length` is 0xfff, which is larger than the possible 509 bytes of `c->operand`. 

But again, this is guarded with a correct sanity check for the size.


### Patch

1. Limiting high positive values for `data_length`:

```c
if (data_length > sizeof(msg->msg) - 4)
  return -EINVAL;
```

Note it is still vulnerable for negative values. 

2. Limiting `write_pos`:

```c
if (write_pos + 4 >= sizeof(c->operand) - 4)
{
  return -EINVAL;
}
```

3. And few more, not too interesting, sanity checks.

## Extra CVEs For Learning

```bash
CVE-2021-43304
CVE-2021-1732 
CVE-2020-0687 
CVE-2021-31320 
CVE-2021-1732
CVE-2020-16010
CVE-2020-1054 
CVE-2020-5734 
CVE-2019-2552 
CVE-2020-1117 
CVE-2021-34423 
```

And [this][project-zero-heap]. 

[project-zero-heap]: https://googleprojectzero.blogspot.com/2019/08/in-wild-ios-exploit-chain-1.html
