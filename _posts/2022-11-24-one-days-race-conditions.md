---
layout: post
title:  "1-Day Research - Race Conditions"
date:   2022-11-24 20:00:01 +0300
categories: jekyll update
---

**Contents**
* TOC
{:toc}
## Background

The root causes are shared resources (either volatile memory, DRAM, or non-volatile memory) & parallelism. \
There are two types of parallelism, faux **multithreading** - 2 tabs executing JS in the same browser, 2 processes on the same OS, 2 OSes in the same hypervisor, and well as true, real **multiprocessing** - 2 CPU cores executing in the same system.  

## TOCTOU, Double Fetches

Common types of RC. \
Double fetches can be very subtle bugs, for example, real CVE from 2013 within the Windows kernel (simplified):

```c
PDWORD BufferSize = /* controlled usermode addr */
...
LocalBuffer = ExAllocatePool(PagedPool, *BufferSize);
if (LocalBuffer) {
	RtlCopyMemory(LocalBuffer, BufferPtr, *BufferSize);
}
```

Due to the double fetch, `*BufferSize` may be altered between its two call sites, obtaining linear OOB-W. \
There's a similiar variant vuln the same researches have found, which involves the following check:

```c
if (*BufferSize < sizeof(LocalBuffer)) {
	err();
}
RtlCopyMemory(LocalBuffer, BufferPtr, *BufferSize);
```

Which is a clear example for TOCTOU vuln.

## Traditional FS-based Races

Worth mentioning. For example:

```c
if (access(pathname, R_OK) == 0)
{
	/*Context switch, create symlink with the original filename, towards our target file*/ 
	fd = open(pathname, O_RDONLY);
	...
}
```

Notice we can take this few steps further. For example, even if the above code adds ANOTHER check, making sure the file is not a symlink (via `stat`), we can perform 3-state swap on our "file swapper" thread, and pass this extra check too. 

## CVE-2021-4207 - QEMU SPICE

In the context of this vuln, the guest VM is the attacker, and the QEMU hypervisor is the target. \
This vuln involves usage of shared memory, that the guest OS controls. 

```c
//XENO: cursor points to Guest OS shared memory, and is thus ACID
static QEMUCursor *qxl_cursor(PCIQXLDevice *qxl, QXLCursor *cursor,
                              uint32_t group_id)
{
    QEMUCursor *c;
    uint8_t *and_mask, *xor_mask;
    size_t size;

    c = cursor_alloc(cursor->header.width, cursor->header.height);
    c->hot_x = cursor->header.hot_spot_x;
    c->hot_y = cursor->header.hot_spot_y;
    switch (cursor->header.type) {
    case SPICE_CURSOR_TYPE_MONO:
        /* Assume that the full cursor is available in a single chunk. */
        size = 2 * cursor_get_mono_bpl(c) * c->height;
        if (size != cursor->data_size) {
            fprintf(stderr, "%s: bad monochrome cursor %ux%u with size %u\n",
                    __func__, c->width, c->height, cursor->data_size);
            goto fail;
        }
        and_mask = cursor->chunk.data;
        xor_mask = and_mask + cursor_get_mono_bpl(c) * c->height;
        cursor_set_mono(c, 0xffffff, 0x000000, xor_mask, 1, and_mask);
        if (qxl->debug > 2) {
            cursor_print_ascii_art(c, "qxl/mono");
        }
        break;
    case SPICE_CURSOR_TYPE_ALPHA:
        size = sizeof(uint32_t) * cursor->header.width * cursor->header.height;
        qxl_unpack_chunks(c->data, size, qxl, &cursor->chunk, group_id);
        if (qxl->debug > 2) {
            cursor_print_ascii_art(c, "qxl/alpha");
        }
        break;
    default:
        fprintf(stderr, "%s: not implemented: type %d\n",
                __func__, cursor->header.type);
        goto fail;
    }
    return c;

fail:
    cursor_put(c);
    return NULL;
}

QEMUCursor *cursor_alloc(int width, int height)
{
    QEMUCursor *c;
    int datasize = width * height * sizeof(uint32_t);

    c = g_malloc0(sizeof(QEMUCursor) + datasize);
    c->width  = width;
    c->height = height;
    c->refcount = 1;
    return c;
}

static void qxl_unpack_chunks(void *dest, size_t size, PCIQXLDevice *qxl,
                              QXLDataChunk *chunk, uint32_t group_id)
{
    uint32_t max_chunks = 32;
    size_t offset = 0;
    size_t bytes;

    for (;;) {
        bytes = MIN(size - offset, chunk->data_size);
        memcpy(dest + offset, chunk->data, bytes);
        offset += bytes;
        if (offset == size) {
            return;
        }
        chunk = qxl_phys2virt(qxl, chunk->next_chunk, group_id);
        if (!chunk) {
            return;
        }
        max_chunks--;
        if (max_chunks == 0) {
            return;
        }
    }
}
```

Because we fully control `cursor` pointer's content, we contol the parameters of the `cursor_alloc` call. In particular, it would perform the following allocation:

```c
int datasize = width * height * sizeof(uint32_t);
c = g_malloc0(sizeof(QEMUCursor) + datasize);
```

Of course, this code snippet seem to be vulnerable to various integer overflows (in addition to the multiplication, also the addition). Notice, it also stores the read `width, height` values as attributes within `c`. Indeed, the `SPICE_CURSOR_TYPE_MONO` cursor type uses these attributes, preventing a double-fetch race vuln. \
However, the `SPICE_CURSOR_TYPE_ALPHA` cursor type does not. In particular, it uses a double fetch, re-calculating the value of `size`:

```c
case SPICE_CURSOR_TYPE_ALPHA:
    size = sizeof(uint32_t) * cursor->header.width * cursor->header.height;
    qxl_unpack_chunks(c->data, size, qxl, &cursor->chunk, group_id);
```

Lets say we'd first supply some low values for `header.width, header.height`. In that case, the corresponding `c` (cursor) would be allocated with that small-value chunk. \
If we'd alter these values in between the `c` allocation, and the call of `qxl_unpack_chunks`, we'd be able to perform linear heap overflow:

```c
for (;;) {
    bytes = MIN(size - offset, chunk->data_size);
    memcpy(dest + offset, chunk->data, bytes);
	...
}
...
```

In particular, we can alter `size` and `chunk->data_size` to be some very large numbers, while having the allocation of `dest` (`c->data`) being very small, obtaining the linear heap overflow. 

## CVE-2020-7460 - FreeBSD sendmsg

Used for sending messages from sockets. In particular, it uses a `struct msghdr` parameter, which has `msg_control, msg_controllen` fields - representing an ancillary data buffer in userspace. \
The ancillary data buffer itself contains `cmsg_len` attribute, as well as `cmsg_level, cmsg_type, cmsg_data` fields. 

```c
/*
 * Copy-in the array of control messages constructed using alignment
 * and padding suitable for a 32-bit environment and construct an
 * mbuf using alignment and padding suitable for a 64-bit kernel.
 * The alignment and padding are defined indirectly by CMSG_DATA(),
 * CMSG_SPACE() and CMSG_LEN().
 */
//XENO: buf is an ACID address/contents userspace buffer, buflen is also ACID
static int
freebsd32_copyin_control(struct mbuf **mp, caddr_t buf, u_int buflen)
{
	struct mbuf *m;
	void *md;
	u_int idx, len, msglen;
	int error;

	buflen = FREEBSD32_ALIGN(buflen);

	if (buflen > MCLBYTES)
		return (EINVAL);

	/*
	 * Iterate over the buffer and get the length of each message
	 * in there. This has 32-bit alignment and padding. Use it to
	 * determine the length of these messages when using 64-bit
	 * alignment and padding.
	 */
	idx = 0;
	len = 0;
	while (idx < buflen) {
		error = copyin(buf + idx, &msglen, sizeof(msglen));
		if (error)
			return (error);
		if (msglen < sizeof(struct cmsghdr))
			return (EINVAL);
		msglen = FREEBSD32_ALIGN(msglen);
		if (idx + msglen > buflen)
			return (EINVAL);
		idx += msglen;
		msglen += CMSG_ALIGN(sizeof(struct cmsghdr)) -
		    FREEBSD32_ALIGN(sizeof(struct cmsghdr));
		len += CMSG_ALIGN(msglen);
	}

	if (len > MCLBYTES)
		return (EINVAL);

	m = m_get(M_WAITOK, MT_CONTROL);
	if (len > MLEN)
		MCLGET(m, M_WAITOK);
	m->m_len = len;

	md = mtod(m, void *);
	while (buflen > 0) {
		error = copyin(buf, md, sizeof(struct cmsghdr));
		if (error)
			break;
		msglen = *(u_int *)md;
		msglen = FREEBSD32_ALIGN(msglen);

		/* Modify the message length to account for alignment. */
		*(u_int *)md = msglen + CMSG_ALIGN(sizeof(struct cmsghdr)) -
		    FREEBSD32_ALIGN(sizeof(struct cmsghdr));

		md = (char *)md + CMSG_ALIGN(sizeof(struct cmsghdr));
		buf += FREEBSD32_ALIGN(sizeof(struct cmsghdr));
		buflen -= FREEBSD32_ALIGN(sizeof(struct cmsghdr));

		msglen -= FREEBSD32_ALIGN(sizeof(struct cmsghdr));
		if (msglen > 0) {
			error = copyin(buf, md, msglen);
			if (error)
				break;
			md = (char *)md + CMSG_ALIGN(msglen);
			buf += msglen;
			buflen -= msglen;
		}
	}

	if (error)
		m_free(m);
	else
		*mp = m;
	return (error);
}
```

This race vuln is an interesting TOCTOU. First, we can pass all checks preceding `md` initialization by simply providing some legitimate `cmsg` buffer. \
Then, we may alter the userspace buffer by having corrupted `cmsg` headers, making the following code snippet to fetch invalid `cmsghdr`, forging a very high value for `msglen`:

```c
error = copyin(buf, md, sizeof(struct cmsghdr));
if (error)
	break;
msglen = *(u_int *)md;
msglen = FREEBSD32_ALIGN(msglen);
```

Recall `md` is actually allocated with some small, legitimate `m->m_len = len` value. \
Hence, we can obtain linear heap-overflow with the last copy:

```c
if (msglen > 0) {
	error = copyin(buf, md, msglen);
	...
}
```

## CVE-2021-34514 - Windows Kernal BALPC



