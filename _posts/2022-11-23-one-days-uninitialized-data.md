---
layout: post
title:  "1-Day Research - Uninitialized Data"
date:   2022-11-23 20:00:01 +0300
categories: jekyll update
---

**Contents**
* TOC
{:toc}
## Background

UDA - Whenever memory isn't initialized, it takes whatever values already in that memory location. 

This becomes a vuln whenever the leftover values are ACID. 

The common 4 cases are:

1. Non initialized stack local variables at declaration time

2. Non initialized heap data at allocation time (`malloc`)

3. Partial initialization of structs, classes and objects (for example, CTOR that sets only part of the object's members).

4. Uncommon control flow path initialization failure - for example, passing a pointer to some "initialization function", which returns earlier than expected, hence leaving the pointer uninitialized. 

## Trivial Example - Stack

```c
void uda_func(int * p){
    int i;
    printf("We all know that %x is leet, right?\n", i);
}

void acid_setter_func(int * p){
    int i = *p;
    printf("We all know that %x is leet, right?\n", i);
}

int main(int argc, char * argv[]){
    char buf[8] = {0};
    int i = 0x1337;
    printf("argc = %d\n", argc);
    if(argc > 1)
    {
        strcpy(buf, argv[1]);
        i = *(int *)(&buf[0]);
    }
    if(buf[0])
    {
        acid_setter_func(&i);
    }
    uda_func(&i);
    return 0;
}
```

The above code initializes `buf` on the stack, within `main`. \
The `i` var value corresponds to the first 4 bytes of the inserted `buf`, interpreted according to an `int`. 

By calling `acid_setter_func`, its new stack frame is allocated, and stores the value of `*p` somewhere of this temporary stack frame. \
The stack unwinding does a simple `add esp`, the values on this temporary allocated frame remains there. \
Therefore, by calling `uda_func` (which has an identical stack frame size and offsets), its local `i` variable is actually initialized to the value we've set via `acid_setter_func`. 

## Trivial Example - Heap

```c
void opt_realloc(char ** buf1, char ** buf2){
    free(*buf1);
    free(*buf2);
    *buf2 = malloc(BUF_SIZE); //XENO: Note, I switched the order of allocs
    *buf1 = malloc(BUF_SIZE); //XENO: This was based on system-specific knowledge
    printf("buf1 addr = %p, buf2 addr = %p\n", *buf1, *buf2);
}

int main(int argc, char * argv[]){
    char * buf1 = malloc(BUF_SIZE);
    char * buf2 = malloc(BUF_SIZE);
    int * i = (int *)buf1;
    printf("buf1 addr = %p, buf2 addr = %p\n", buf1, buf2);
    printf("argc = %d\n", argc);
    if(argc > 1)
    {
        strcpy(buf1, argv[1]);
        memset(buf2, '!', BUF_SIZE);
    }
    if(buf1[0])
    {
        opt_realloc(&buf1, &buf2);
    }
    for(unsigned int j = 0; j < strlen(argv[1])/4; j++)
    {
        printf("At %p+%d:\t %x\n", i, j*4, *(int *)(i+j));
    }
    i = (int *)buf2;
    printf("\n");
    for(unsigned int j = 0; j < strlen(argv[1])/4; j++)
    {
        printf("At %p+%d:\t %x\n", i, j*4, *(int *)(i+j));
    }
    printf("At the end of the day, the important thing is: %x\n", *(int *)&buf1[16]);
    return 0;
}
```

This code has few problems: the `malloc` calls return values aren't checked, arbitrary `strcpy` to `buf1` from `argv[1]`, off-by-one by the `memset(buf2)` call (as it doesn't takes into account the terminating null-byte).

However, the main focus of this vuln is within `opt_realloc`. \
This function `free`s the allocated chunks, and re-allocates them by the original order (note that the LIFO / FIFO pattern is both platform dependent, as well as allocator and chunk size dependent). 

This means that after the call to `opt_realloc`, both loops would print content of the buffers. \
Note, that some of the printed values would now be garbage! \
This is because the `free` and subsequent `malloc` call would reuse heap memory. 

For example, while freeing `buf2`, the `free` call have set its `fd` pointer towards the freed prior chunk, `buf1`. \
This means that the `free` call have reused this qword address, and 
because `fd` overlaps the `user_content`, printing `buf2` would show some reused heap memory of the `buf1` chunk - and would give us a heap leakage primitive!

The core vuln here, is that `malloc` actually returns uninitialized data. \
Therefore, prefer using `calloc(1, size)` instead. 

Note that in this particular case, even `memset_s` the buffer prior to `free`ing them wouldn't prevent the heap leakage, as the second `free` call sets the first qword of `buf2` to a heap address. 

## Exploitation

For stack and heap UDA, mostly stack grooming ("stack feng shui") and heap feng shui. 

The idea is to call functions in an order that leads to ACID being placed on the correct memory address, that will eventually be read by the function containing the UDA vuln. 

Heap feng shui, as opposed to regular heap overflow, would fill the user-data of the allocated chunks with ACID, then free some of the chunks, and allocate the victim chunks (that contains uninitialized data). \
Now those chunks containing some user-data that is ACID. 

It makes heap-spraying a very good strategy, so that most addresses on the heap will containg ACID with high probability (allocate alot of chunks, fill them with ACID, and free them all). 

## CVE-2022-1809 - Radare2

RE tool. \
Therefore, all values that come from the binary are actually ACID. 

### Code

```c
//////////////////////////////////////////////////////////////////////
//XENO: Structure that isn't completely initialized
//////////////////////////////////////////////////////////////////////
/* vtables */
typedef struct {
	RAnal *anal;
	RAnalCPPABI abi;
	ut8 word_size;
	bool (*read_addr) (RAnal *anal, ut64 addr, ut64 *buf);
} RVTableContext;

//////////////////////////////////////////////////////////////////////
//XENO: Part of the path where incomplete initialized occurs
//////////////////////////////////////////////////////////////////////

//XENO: assume the following fields are ACID based on a malicious ACID binary under analysis:
//XENO: anal->config->bits, anal->cur->arch

R_API bool r_anal_vtable_begin(RAnal *anal, RVTableContext *context) {
	context->anal = anal;
	context->abi = anal->cxxabi;
	context->word_size = (ut8) (anal->config->bits / 8);
	const bool is_arm = anal->cur->arch && r_str_startswith (anal->cur->arch, "arm");
	if (is_arm && context->word_size < 4) {
		context->word_size = 4;
	}
	const bool be = anal->config->big_endian;
	switch (context->word_size) {
	case 1:
		context->read_addr = be? vtable_read_addr_be8 : vtable_read_addr_le8;
		break;
	case 2:
		context->read_addr = be? vtable_read_addr_be16 : vtable_read_addr_le16;
		break;
	case 4:
		context->read_addr = be? vtable_read_addr_be32 : vtable_read_addr_le32;
		break;
	case 8:
		context->read_addr = be? vtable_read_addr_be64 : vtable_read_addr_le64;
		break;
	default:
		return false;
	}
	return true;
}

//////////////////////////////////////////////////////////////////////
//XENO: Part of the path where uninitialized access occurs eventually
//////////////////////////////////////////////////////////////////////


R_API void r_anal_list_vtables(RAnal *anal, int rad) {
	RVTableContext context;
	r_anal_vtable_begin (anal, &context);

	const char *noMethodName = "No Name found";
	RVTableMethodInfo *curMethod;
	RListIter *vtableIter;
	RVTableInfo *table;

	RList *vtables = r_anal_vtable_search (&context);
//XENO: snip
}

R_API RList *r_anal_vtable_search(RVTableContext *context) {
	RAnal *anal = context->anal;
	if (!anal) {
		return NULL;
	}

	RList *vtables = r_list_newf ((RListFree)r_anal_vtable_info_free);
	if (!vtables) {
		return NULL;
	}

	RList *sections = anal->binb.get_sections (anal->binb.bin);
	if (!sections) {
		r_list_free (vtables);
		return NULL;
	}

	r_cons_break_push (NULL, NULL);

	RListIter *iter;
	RBinSection *section;
	r_list_foreach (sections, iter, section) {
		if (r_cons_is_breaked ()) {
			break;
		}

		if (!vtable_section_can_contain_vtables (section)) {
			continue;
		}

		ut64 startAddress = section->vaddr;
		ut64 endAddress = startAddress + (section->vsize) - context->word_size;
		ut64 ss = endAddress - startAddress;
		if (ss > ST32_MAX) {
			break;
		}
		while (startAddress <= endAddress) {
			if (r_cons_is_breaked ()) {
				break;
			}
			if (!anal->iob.is_valid_offset (anal->iob.io, startAddress, 0)) {
				break;
			}

			if (vtable_is_addr_vtable_start (context, section, startAddress)) {
				RVTableInfo *vtable = r_anal_vtable_parse_at (context, startAddress);
				if (vtable) {
					r_list_append (vtables, vtable);
					ut64 size = r_anal_vtable_info_get_size (context, vtable);
					if (size > 0) {
						startAddress += size;
						continue;
					}
				}
			}
			startAddress += context->word_size;
		}
	}
//XENO: snip
}

static bool vtable_is_addr_vtable_start(RVTableContext *context, RBinSection *section, ut64 curAddress) {
	if (context->abi == R_ANAL_CPP_ABI_MSVC) {
		return vtable_is_addr_vtable_start_msvc (context, curAddress);
	}
	if (context->abi == R_ANAL_CPP_ABI_ITANIUM) {
		return vtable_is_addr_vtable_start_itanium (context, section, curAddress);
	}
	r_return_val_if_reached (false);
	return false;
}

static bool vtable_is_addr_vtable_start_msvc(RVTableContext *context, ut64 curAddress) {
	RAnalRef *xref;
	RListIter *xrefIter;

	if (!curAddress || curAddress == UT64_MAX) {
		return false;
	}
	if (curAddress && !vtable_is_value_in_text_section (context, curAddress, NULL)) {
		return false;
	}
//XENO: snip
}

static bool vtable_is_value_in_text_section(RVTableContext *context, ut64 curAddress, ut64 *value) {
	//value at the current address
	ut64 curAddressValue;
	if (!context->read_addr (context->anal, curAddress, &curAddressValue)) {
		return false;
	}
	//if the value is in text section
	bool ret = vtable_addr_in_text_section (context, curAddressValue);
	if (value) {
		*value = curAddressValue;
	}
	return ret;
}
```

### Code Review

Initially, `RVTableContext context` is allocated on the stack, without any initialization. \
Then, the initialization function `r_anal_vtable_begin` initializes *some* of the struct's members. \
Since `word_size` is ACID, we can control the switch-case branch, so that non of the criterias are met. \
This means that we can leave `context->read_addr` as uninitialized function pointer. 

Since `r_anal_vtable_begin` returns the value of `false` in such case, but its return value isn't checked - we are completely OK, and the flow continues. 

This function pointer is being used at `vtable_is_value_in_text_section`. 

If we groom the stack into having an ACID `read_addr` field, we win. 

### Patch

Added `RVTableContext context = {0};` (insufficient, as there are also other flows reaching the vuln).

Also added `read_addr` initialization to some default value, which fixes the core bug. 

## CVE-2021-3608 - QEMU Paravirtualized RDMA

```c
typedef struct PvrdmaRing {
    char name[MAX_RING_NAME_SZ];
    PCIDevice *dev;
    uint32_t max_elems;
    size_t elem_sz;
    PvrdmaRingState *ring_state; /* used only for unmap */
    int npages;
    void **pages;
} PvrdmaRing;


// Assume dir_addr and num_pages are ACID
static int init_dev_ring(PvrdmaRing *ring, PvrdmaRingState **ring_state,
                         const char *name, PCIDevice *pci_dev,
                         dma_addr_t dir_addr, uint32_t num_pages)
{
    uint64_t *dir, *tbl;
    int rc = 0;

    dir = rdma_pci_dma_map(pci_dev, dir_addr, TARGET_PAGE_SIZE);
    if (!dir) {
        rdma_error_report("Failed to map to page directory (ring %s)", name);
        rc = -ENOMEM;
        goto out;
    }
    tbl = rdma_pci_dma_map(pci_dev, dir[0], TARGET_PAGE_SIZE);
    if (!tbl) {
        rdma_error_report("Failed to map to page table (ring %s)", name);
        rc = -ENOMEM;
        goto out_free_dir;
    }

    *ring_state = rdma_pci_dma_map(pci_dev, tbl[0], TARGET_PAGE_SIZE);
    if (!*ring_state) {
        rdma_error_report("Failed to map to ring state (ring %s)", name);
        rc = -ENOMEM;
        goto out_free_tbl;
    }
    /* RX ring is the second */
    (*ring_state)++;
    rc = pvrdma_ring_init(ring, name, pci_dev,
                          (PvrdmaRingState *)*ring_state,
                          (num_pages - 1) * TARGET_PAGE_SIZE /
                          sizeof(struct pvrdma_cqne),
                          sizeof(struct pvrdma_cqne),
                          (dma_addr_t *)&tbl[1], (dma_addr_t)num_pages - 1);
    if (rc) {
        rc = -ENOMEM;
        goto out_free_ring_state;
    }

    goto out_free_tbl;

out_free_ring_state:
    rdma_pci_dma_unmap(pci_dev, *ring_state, TARGET_PAGE_SIZE);

out_free_tbl:
    rdma_pci_dma_unmap(pci_dev, tbl, TARGET_PAGE_SIZE);

out_free_dir:
    rdma_pci_dma_unmap(pci_dev, dir, TARGET_PAGE_SIZE);

out:
    return rc;
}

int pvrdma_ring_init(PvrdmaRing *ring, const char *name, PCIDevice *dev,
                     PvrdmaRingState *ring_state, uint32_t max_elems,
                     size_t elem_sz, dma_addr_t *tbl, uint32_t npages)
{
    int i;
    int rc = 0;

    pstrcpy(ring->name, MAX_RING_NAME_SZ, name);
    ring->dev = dev;
    ring->ring_state = ring_state;
    ring->max_elems = max_elems;
    ring->elem_sz = elem_sz;
    /* TODO: Give a moment to think if we want to redo driver settings
    qatomic_set(&ring->ring_state->prod_tail, 0);
    qatomic_set(&ring->ring_state->cons_head, 0);
    */
    ring->npages = npages;
    ring->pages = g_malloc(npages * sizeof(void *)); //XENO: array of npages pointers

    for (i = 0; i < npages; i++) {
        if (!tbl[i]) {
            rdma_error_report("npages=%d but tbl[%d] is NULL", npages, i);
            continue;
        }

        ring->pages[i] = rdma_pci_dma_map(dev, tbl[i], TARGET_PAGE_SIZE);
        if (!ring->pages[i]) {
            rc = -ENOMEM;
            rdma_error_report("Failed to map to page %d in ring %s", i, name);
            goto out_free;
        }
        memset(ring->pages[i], 0, TARGET_PAGE_SIZE);
    }

    goto out;

out_free:
    while (i--) {
        rdma_pci_dma_unmap(dev, ring->pages[i], TARGET_PAGE_SIZE);
    }
    g_free(ring->pages);

out:
    return rc;
}
```

Recall we control `npages`. The following call returns an uninitalized chunk: `ring->pages = g_malloc(npages * sizeof(void *));`. \
While there's initialization attempt within the loop, using `memset` call, it is only invoked incase `tbl[i]` (source) isn't null. Otherwise, it would leave the destination buffer, `ring->pages`, as uninitialized. \
This vuln is particularly interesting, as right after the "initialization" process, `out_free` is called to perform the cleanup. But due to uninitialized values of `ring->pages[i]`, it would attempt to call `dma_unmap` on an uninitialized heap data - which might be controlled!

## CVE-2022-26721 - Apple XPC

```c
xpc_object_t content = xpc_dictionary_get_value(req, "source");
	size_t count = xpc_array_get_count(content); //XENO: count SACI, based on number of array elements sent
	size_t *descriptors = malloc(sizeof(size_t) * 4 * count);
	size_t *accessBeginPointer = &descriptors[count * 0],
	  *accessDataLength = &descriptors[count * 1],
	  *mappedBaseAddress = &descriptors[count * 2],
	  *mappedLength = &descriptors[count * 3];

	for(size_t i = 0; i < count; i++) {
	  accessBeginPointer[i] = accessDataLength[i] =
	  mappedBaseAddress[i] = mappedLength[i] = 0;

	  xpc_object_t chunk = xpc_array_get_value(content, i);

	  if(xpc_get_type(chunk) == XPC_TYPE_DATA) { /*...*/ }
	  else if(xpc_get_type(chunk) == XPC_TYPE_SHMEM) {
	    xpc_object_t map = xpc_array_get_value(chunk, 0);
	    size_t offset = min(xpc_array_get_uint64(chunk, 1), 0xFFF), //XENO: offset SACI
	    size = xpc_array_get_uint64(chunk, 2);                      //XENO: size ACID

	    size_t mapped_address;
	    size_t mapped_size = xpc_shmem_map(map, &mapped_address);   //XENO: mapped_size ACID

		if(mapped_size < offset) break;

	    size = min(size, mapped_size - offset);
	    // ...
	  }
	}
	// ...
	// cleanup
	for(size_t index = 0; index < count; index++) {
	  if(mappedLength[index]) {
	    munmap(
	      mappedBaseAddress[index],
	      mappedLength[index]
	    );
	  }
	}
	free(descriptors);
```

The target buffer is `descriptors`, which isn't initialized right after being allocated. \
In fact, its initialization is performed within the `for` loop. If we'd trigger the `break` criteria, the loop would stop, and won't initialize the rest of the elements. \
Notice, that even without the `break` statement, If we'd send `count == 0`, the `for` loop won't be entered, and depending on the allocator - a valid chunk might be returned. In that case, the cleanup handlers would be called - dispatching `munmap` on uninitalized content. \
Another problematic aspect of this code, is the fact that `mapped_address` isn't initialized at all. 

## CVE-2022-29968 - "Lord Of The io_urings"


