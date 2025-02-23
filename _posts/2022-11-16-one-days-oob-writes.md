---
layout: post
title:  "1-Day Research - OOB Writes"
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

Note: there are cases where OOB is way stronger than regular BOF. \
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

### Code

```c
////ACID: g_font->numMasters
int ParseBlendVToHOrigin(void *arg) {
  Fixed16_16 *ptrs[2];
  Fixed16_16 values[2];

  for (int i = 0; i < g_font->numMasters; i++) { //KC: 0 <= g_font->numMasters <= 16
    ptrs[i] = &g_font->SomeArray[arg->SomeField + i];
  }

  for (int i = 0; i < 2; i++) {        //KC: values becomes ACID here
    int values_read = GetOpenFixedArray(values, g_font->numMasters);
    if (values_read != g_font->numMasters) {
      return -8;
    }

    for (int num = 0; num < g_font->numMasters; num++) {
      ptrs[num][i] = values[num];
    }
  }

  return 0;
}
```

### Code Review

1. Uninitialized local buffers `ptrs, values`.

2. Since `g_font->numMasters` is controlled, we control the loop iteration count.\
Note `i` is defined as a signed integer (so there might have been integer overflow). \
However, the iteration count is still limited to `0 <= num <= 16`.\
There is a clear OOB write, as `ptrs` is an array of only two pointers. \
Note there is also possible OOB read of the source `SomeArray[]`, depending on its size. However, this array is not attacker-controlled. \
By setting the iteration count to `numMasters >= 3`, attacker may override memory beyond `ptrs[]`. (Note this is compiler-dependent, as the locals order on the stack may be opposite. Usually MSVC have reverse locals order compares to gcc).

3. `values_read` is defined as int, instead of uint. 

4. The second loop allows controlling the exact content of `ptrs` array.

`values` is controlled by `GetOpenFixedArray`, and there is another OOB write as `numMasters` is attacker-controlled. \
Therefore there is an OOB for the `values` array. 

5. The last loop allows OOB write of controlled data, `values`, to the return address, which is beyond `ptrs`. 

### Patch

The arrays were updated to 16 elements, each.

Moreover, a check was added for `g_font->numMasters <= 1`


## CVE-2020-13995  - NITF Parser

### Code

```c
//XENO: Globals
char Gstr[255];
char sBuffer[1000];
//...
/* V2_0, V2_1 */
int number_of_DESs;
segment_info_type *DES_info;
//...
long read_verify(int fh, char *destination, long length, char *sErrorMessage)
{
    long rc;
    long start;
    long file_len;
    static char sTemp[150];

    rc = read(fh, destination, length);
    if (rc == -1) {
        start = lseek(fh, 0, SEEK_CUR);
        file_len = lseek(fh, 0, SEEK_END);
        sprintf(sTemp, "Error reading, read returned %ld. (start = %ld, \
read length = %ld, file_length = %ld\n%s\n",
                    rc, start, length, file_len, sErrorMessage);
        errmessage(sTemp);
        iQuit(1);
    }
    else if (rc != length) {
        start = lseek(fh, 0, SEEK_CUR) - rc;
        file_len = lseek(fh, 0, SEEK_END);
        sprintf(sTemp, "Error reading, read returned %ld. (start = %ld, \
read length = %ld, file_length = %ld\n%s\n",
                    rc, start, length, file_len, sErrorMessage);
        errmessage(sTemp);
        printf("errno=%d\n", errno);
        iQuit(1);
    }
    return rc;
}

////ACID: hNITF
int main(int argc, char *argv[]){
	//...
    rc = open(sNITFfilename, O_RDONLY| O_BINARY);
	//...
    hNITF = rc;
	//...
	read_verify(hNITF, (char *) sBuffer, 3,
	                "error reading header (# extension segs");
	    sBuffer[3] = '\0';
	    number_of_DESs = atoi(sBuffer);

	    if (number_of_DESs > 0) {
	        /* Allocate Space for extension segs information arrays */
	        DES_info = (segment_info_type *)
	                 malloc(sizeof(segment_info_type) * number_of_DESs);
	        if (DES_info == NULL) {
	            errmessage("Error allocating memory for DES_info");
	            iQuit(1);
	        }

	        /* Read Image subheader / data lengths */

	        read_verify(hNITF, sBuffer, 13 * number_of_DESs,
	            "Error reading header / image subheader data lengths");

	        temp = sBuffer;

	        for (x = 0; x < number_of_DESs; x++) {
	            strncpy(Gstr, temp, 4);
	            Gstr[4] = '\0';
	            DES_info[x].length_of_subheader = atol(Gstr);
	            temp += 4;

	            strncpy(Gstr, temp, 9);
	            Gstr[9] = '\0';
	            DES_info[x].length_of_data = atol(Gstr);
	            temp += 9;

	            DES_info[x].pData = NULL;
	            DES_info[x].bFile_written = FALSE;
	        }
	    }
}
```

### Code Review

1. No check for `open` success value.

2. `read_verify` - partially controlled stack buffer overflow. 
A `sprintf()` is being used, for a buffer of length 150 bytes. \
The longest entered string is about 50 bytes: `"Error reading header / image subheader data lengths"`. \
Moreover, every `%ld` specifier may take up to 19 bytes, due to largest possible value of `9223372036854775807`. 

3. Integer overflow that can lead to heap under-allocation: \
Since attacker may control `number_of_DESs`, it may tweak the `malloc` call:

```c
malloc(sizeof(segment_info_type) * number_of_DESs);
```

In case `sizeof(segment_info_type) * number_of_DESs` overflows, for example `sizeof() == 16` and `number == 0x10000000`, it will result with `malloc(0)`, hence malloc returning a zero-length buffer, allowing easy heap buffer overflow. \
Note this isn't trivialally exploitable, as only the first 3 bytes of the file serves as the length, hence resulting with maximal length of `0x00ffffff`. \
In case `sizeof(segment_info_type) > 16`, this IS exploitable tho. \
Another possibilty is to insert huge `number_of_DESs` (up to `0x00ffffff`), as there is no size check at all, and perform huge buffer allocation.


4. Another integer overflow + OOB write:

```c
read_verify(hNITF, sBuffer, 13 * number_of_DESs);
```

Like previously, may set `number_of_DESs` so that overflow would occur, and it will verify 0 bytes, and the check would pass. \
Moreover, `sBuffer` is a fixed-size buffer, while `number_of_DESs` is controlled. \
Trivial buffer OOB write. 

5. OOB Write, exploitable in case of an under-allocated heap memory for `DES_info`:

```c
for (x = 0; x < number_of_DESs; x++) {
	            strncpy(Gstr, temp, 4);
	            Gstr[4] = '\0';
	            DES_info[x].length_of_subheader = atol(Gstr);
	            temp += 4;

	            strncpy(Gstr, temp, 9);
	            Gstr[9] = '\0';
	            DES_info[x].length_of_data = atol(Gstr);
	            temp += 9;

	            DES_info[x].pData = NULL;
	            DES_info[x].bFile_written = FALSE;
	        }
```

`number_of_DESs` is fully controlled, and contains some positive value. \
In case of an under-allocation of the heap (due to integer overflow), `DES_info` will be overflowed by attacker-controlled input (as `Gstr` is crafted by the file's content). \

6. OOB read - 

`number_of_DESs` is controlled, and `temp = sBuffer` is a fixed-size static buffer. \
For large `number_of_DESs` value, `temp` would be increased over and over, yielding OOB read towards the `Gstr` buffer, hence towards `DES_info`.

### Patch

None.


## CVE-2020-27930 - Apple Fonts - libType1Scaler.dylib

### Code

```c
int op_stk[64];
int *op_sp;

int n = POP();

op_sp -= n;

if (op_sp < &op_stk[0]>)
{ exit(1);}
...
```

### Code Review

1. The number of elements of the stack, `n`, is controlled by the attacker. It determines the value of `op_sp`, which is also attacker-controlled. 

2. While there is correct lower bounds check, there is no signess check for n. 

Therfore, it is possible to set negative `n` value, and actually increase `op_sp`, without any sanity check being made.


### Patch

No released patch.

## CVE-2021-26675 - T-BONE

```C
static char *uncompress(int16_t field_count, 	/*KC: ACID from packet header */
                        char *start,            /*KC: Starting header of ACID input packet */
                        char *end,              /*KC: End of ACID input packet */
                        char *ptr,              /*KC: Current offset in ACID input packet */
                        char *uncompressed,     /*KC: Base of [1025] output buffer */
                        int uncomp_len,         /*KC: Hardcoded 1025 */
                        char **uncompressed_ptr)/*KC: Offset to end of uncompressed data */
{
	char *uptr = *uncompressed_ptr; /* position in result buffer */

	debug("count %d ptr %p end %p uptr %p", field_count, ptr, end, uptr);

	while (field_count-- > 0 && ptr < end) {
		int dlen;		/* data field length */
		int ulen;		/* uncompress length */
		int pos;		/* position in compressed string */
		char name[NS_MAXLABEL]; /* tmp label */ /*KC: fixed-size 63 byte buffer*/
		uint16_t dns_type, dns_class;
		int comp_pos;

		if (!convert_label(start, end, ptr, name, NS_MAXLABEL,
					&pos, &comp_pos))
			goto out;

		/*
		 * Copy the uncompressed resource record, type, class and \0 to
		 * tmp buffer.
		 */

		ulen = strlen(name);
		strncpy(uptr, name, uncomp_len - (uptr - uncompressed)); /*KC: 1025 - (current offset-base) */

		debug("pos %d ulen %d left %d name %s", pos, ulen,
			(int)(uncomp_len - (uptr - uncompressed)), uptr);

		uptr += ulen;
		*uptr++ = '\0';

		ptr += pos;

		/*
		 * We copy also the fixed portion of the result (type, class,
		 * ttl, address length and the address)
		 */
		memcpy(uptr, ptr, NS_RRFIXEDSZ); /*KC: NS_RRFIXEDSZ = 10*/

		dns_type = uptr[0] << 8 | uptr[1];
		dns_class = uptr[2] << 8 | uptr[3];

		if (dns_class != ns_c_in)
			goto out;

		ptr += NS_RRFIXEDSZ;
		uptr += NS_RRFIXEDSZ
```

### Code Review

1. OOB Write - `name` is 63 bytes array, with fully ACID data.
Therefore, attacker may set these 63 bytes to be non null-terminated, as `strlen` stops its iteration only if `\x00` is occured. 

It means that `ulen` may actually exceed 63 bytes.

```c
ulen = strlen(name);
```

Note - this actually depends on the implementation of `convert_label`: in case it checks the `name` is actually null-termination, the above doesn't hold, and `ulen` would be up to 62 bytes. 


4. OOB Write - 

```c
ulen = strlen(name);
strncpy(uptr, name, uncomp_len - (uptr - uncompressed));

uptr += ulen;
*uptr++ = '\0';

ptr += pos;

memcpy(uptr, ptr, NS_RRFIXEDSZ); /*KC: NS_RRFIXEDSZ = 10*/
```

Since we control `ptr` content and `field_count`, we can fill the `uptr` array for up to 1025 bytes via multiple iterations to `name` copying. 

At a first glance this seems OK - as it copies up to maximum of 1025 bytes.

However - instead of advancing `uptr` by the amount of copied data (`uncomp_len - (uptr - uncompressed)`), it is advanced by `ulen`, regardless of the copied amount of bytes.

For the last iteration, attacker may set the amount of copied data to exactly 0 bytes, while setting `ulen` to 62 bytes.
This allows OOB write for the `uptr` array. 

Another problem is that a second `memcpy` is being issued, without any boundaries check. 

It results with an overflow of `NS_RRFIXEDSZ` bytes.

Last but not least, the next iteration will have a negative number of copied bytes, as now `uncomp_len - (uptr - uncompressed) < 0`, and results with an integer overflow.

This leads to an unbounded overflow. 

### Patch

```c
char * const uncomp_end = uncompressed + uncomp_len - 1;

if ((uptr + ulen + 1) > uncomp_end)
  goto out;

if ((uptr + NS_RRFIXEDSZ < uncomp_end))
  goto out;
```

## CVE-2021-28216 - UEFI FirmwarePerformance NV VAR

### Code

```c
////ACID: NV Var data returned in PerformanceVariable
////NOT ACID: Variables named *Guid
//
// Update S3 boot records into the basic boot performance table.
//
VarSize = sizeof (PerformanceVariable);
Status = VariableServices->GetVariable(VariableServices,
                                       EFI_FIRMWARE_PERFORMANCE_VARIABLE_NAME,
                                       &gEfiFirmwarePerformanceGuid,
                                       NULL,
                                       &VarSize,
                                       &PerformanceVariable);
if (EFI_ERROR (Status)) {
	return Status;
}
BootPerformanceTable = (UINT8*) (UINTN)PerformanceVariable.BootPerformanceTablePointer;
//
// Dump PEI boot records
//
FirmwarePerformanceTablePtr = (BootPerformanceTable + sizeof(BOOT_PERFORMANCE_TABLE));

GuidHob = GetFirstGuidHob(&gEdkiiFpdtExtendedFirmwarePerformanceGuid);

while (GuidHob != NULL) {
	FirmwarePerformanceData = GET_GUID_HOB_DATA(GuidHob);
	PeiPerformanceLogHeader = (FPDT_PEI_EXT_PERF_HEADER *)FirmwarePerformanceData;
	CopyMem(FirmwarePerformanceTablePtr,
			FirmwarePerformanceData + sizeof (FPDT_PEI_EXT_PERF_HEADER),
			(UINTN)(PeiPerformanceLogHeader->SizeOfAllEntries));

	GuidHob = GetNextGuidHob(&gEdkiiFpdtExtendedFirmwarePerformanceGuid, GET_NEXT_HOB(GuidHob));
	FirmwarePerformanceTablePtr += (UINTN)(PeiPerformanceLogHeader->SizeOfAllEntries);
}
//
// Update Table length.
//
((BOOT_PERFORMANCE_TABLE *) BootPerformanceTable)->Header.Length =
		(UINT32)((UINTN)FirmwarePerformanceTablePtr - (UINTN)BootPerformanceTable);
```

### Code Review

1. OOB Write - 

Attacker may control the pointers `BootPerformanceTable` and `FirmwarePerformanceTablePtr`, which is the destination of the `CopyMem` call. \
Note this isn't attacker controlled data.

2. Another OOB Write - 

The last write enables write of the value of at least `sizeof(BOOT_PERFORMANCE_TABLE)` to any address. 

### Patch

Refactored all of this crappy mechanism. 


## CVE-2022-25636 - Linux Kernel nft_fwd_dup_netdev_offload

Netfilter is a LKM that provides firewall, NAT, packet managing for linux. 

Commonly interacted via the iptables mechanism.

The `nft` user app, allows specifying a set of firewall rules. 
These rules are parsed and handled by the kernel module. 

### Code

```c
struct flow_action {
	unsigned int               num_entries;
	struct flow_action_entry   entries[];
};

struct flow_rule {
	struct flow_match          match;
	struct flow_action         action;
};

struct nft_flow_rule {
	__be16                     proto;
	struct nft_flow_match      match;
	struct flow_rule           *rule;
};

struct nft_offload_ctx {
	struct {
		enum nft_offload_dep_type   type;
		__be16                      l3num;
		u8                          protonum;
	} dep;
	unsigned int               num_actions;
	struct net                 *net;
	struct nft_offload_reg     regs[NFT_REG32_15 + 1];
};

/**
 * struct_size() - Calculate size of structure with trailing array.
 * @p: Pointer to the structure.
 * @member: Name of the array member.
 * @count: Number of elements in the array.
 *
 * Calculates size of memory needed for structure @p followed by an
 * array of @count number of @member elements.
 *
 * Return: number of bytes needed or SIZE_MAX on overflow.
 */
#define struct_size(p, member, count)					\
	__ab_c_size(count,						\
		    sizeof(*(p)->member) + __must_be_array((p)->member),\
		    sizeof(*(p)))

#define NFT_OFFLOAD_F_ACTION	(1 << 0)

struct flow_rule *flow_rule_alloc(unsigned int num_actions)
{
	struct flow_rule *rule;
	int i;
	// XENO: allocates space for the rule->action.entries[num_actions] array
	rule = kzalloc(struct_size(rule, action.entries, num_actions),
		       GFP_KERNEL);
	if (!rule)
		return NULL;

	rule->action.num_entries = num_actions;
	/* Pre-fill each action hw_stats with DONT_CARE.
	 * Caller can override this if it wants stats for a given action.
	 */
	for (i = 0; i < num_actions; i++)
		rule->action.entries[i].hw_stats = FLOW_ACTION_HW_STATS_DONT_CARE;

	return rule;
}

static struct nft_flow_rule *nft_flow_rule_alloc(int num_actions)
{
	struct nft_flow_rule *flow;

	flow = kzalloc(sizeof(struct nft_flow_rule), GFP_KERNEL);
	if (!flow)
		return NULL;

	flow->rule = flow_rule_alloc(num_actions);
	if (!flow->rule) {
		kfree(flow);
		return NULL;
	}

	flow->rule->match.dissector	= &flow->match.dissector;
	flow->rule->match.mask		= &flow->match.mask;
	flow->rule->match.key		= &flow->match.key;

	return flow;
}

static inline struct nft_expr *nft_expr_first(const struct nft_rule *rule)
{
	return (struct nft_expr *)&rule->data[0];
}

static inline struct nft_expr *nft_expr_last(const struct nft_rule *rule)
{
	return (struct nft_expr *)&rule->data[rule->dlen];
}

static inline bool nft_expr_more(const struct nft_rule *rule,
				 const struct nft_expr *expr)
{
	return expr != nft_expr_last(rule) && expr->ops;
}


int nft_fwd_dup_netdev_offload(struct nft_offload_ctx *ctx,
			       struct nft_flow_rule *flow,
			       enum flow_action_id id, int oif)
{
	struct flow_action_entry *entry;
	struct net_device *dev;

	/* nft_flow_rule_destroy() releases the reference on this device. */
	dev = dev_get_by_index(ctx->net, oif);
	if (!dev)
		return -EOPNOTSUPP;

	entry = &flow->rule->action.entries[ctx->num_actions++];
	entry->id = id;
	entry->dev = dev;

	return 0;
}

static inline void *nft_expr_priv(const struct nft_expr *expr)
{
	return (void *)expr->data;
}

static int nft_dup_netdev_offload(struct nft_offload_ctx *ctx,
				  struct nft_flow_rule *flow,
				  const struct nft_expr *expr)
{
	const struct nft_dup_netdev *priv = nft_expr_priv(expr); // XENO: assume priv != ACID
	int oif = ctx->regs[priv->sreg_dev].data.data[0];

	return nft_fwd_dup_netdev_offload(ctx, flow, FLOW_ACTION_MIRRED /*5*/, oif);
}

////ACID: rule
struct nft_flow_rule *nft_flow_rule_create(struct net *net,
					   const struct nft_rule *rule)
{
	struct nft_offload_ctx *ctx;
	struct nft_flow_rule *flow;
	int num_actions = 0, err;
	struct nft_expr *expr;

	expr = nft_expr_first(rule);
	while (nft_expr_more(rule, expr)) {
		if (expr->ops->offload_flags & NFT_OFFLOAD_F_ACTION)
			num_actions++;

		expr = nft_expr_next(expr);
	}

	if (num_actions == 0)
		return ERR_PTR(-EOPNOTSUPP);

	flow = nft_flow_rule_alloc(num_actions);
	if (!flow)
		return ERR_PTR(-ENOMEM);

	expr = nft_expr_first(rule);

	ctx = kzalloc(sizeof(struct nft_offload_ctx), GFP_KERNEL);
	if (!ctx) {
		err = -ENOMEM;
		goto err_out;
	}
	ctx->net = net;
	ctx->dep.type = NFT_OFFLOAD_DEP_UNSPEC;

	while (nft_expr_more(rule, expr)) {
		if (!expr->ops->offload) {
			err = -EOPNOTSUPP;
			goto err_out;
		}
		err = expr->ops->offload(ctx, flow, expr); //XENO: Calls nft_dup_netdev_offload()
		if (err < 0)
			goto err_out;

		expr = nft_expr_next(expr);
	}
	nft_flow_rule_transfer_vlan(ctx, flow);

	flow->proto = ctx->dep.l3num;
	kfree(ctx);

	return flow;
err_out:
	kfree(ctx);
	nft_flow_rule_destroy(flow);

	return ERR_PTR(err);
}
```

### Code Review

1. `nft_flow_rule_create` receives `rule` as a userland data. 

`expr` states the current processed expression, which is also controlled by the user.

`int num_actions` also controlled, but defined as a signed int instead of uint. 
Note that `flow_rule_alloc()` implicitly converts it to uint. 

2. OOB write

Attacker may control the size of the allocated `flow` pointer, by setting `num_actions` to some low value.
This results with very small allocated chunk for `flow->rule->action.entries`. 

For example, setting many expressions - but most of them dont have the `NFT_OFFLOAD_F_ACTION` flag enabled.

Afterwards, each `expr` issues `expr->ops->offload`, triggering many calls for `nft_dup_netdev_offload()`.

Then, `nft_fwd_dup_netdev_offload` is called, triggering:

```c
entry = &flow->rule->action.entries[ctx->num_actions++];
entry->id = id;
entry->dev = dev;
```

For *every* expression within the rule, not only actions. Meaning - `ctx->num_actions` can grow unbounded. 

That results with an OOB write - as `entry` is initialzied by some overflowed address.
`entry->id , entry->dev` content are overwritten, according to the values within `id , dev`. 

### Patch

The while loop counting `num_actions` was changed, and instead of using an attacker-controlled flag, it counts `actions`.


## UBSan

Undefined-behavior sanitizer. 

Similar to ASan, find bugs in runtime. Its overhead is small, so it might be even recommended to run it in production build.

### Bounds sanitizer

Checks for OOB read / writes. 
Just add `-fsanitize=bounds` to add the runtime checks 

### Pointer Overflow

Checks at runtime for wraps around, for example 64-bit addrs wraps. 
(This may result by an access to lower addresses from the base pointer). 

Add `-fsanitize=pointer-overflow` for these runtime checks. 
