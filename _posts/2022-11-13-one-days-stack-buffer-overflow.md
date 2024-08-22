---
layout: post
title:  "1'Days Research - Stack Buffer Overflows"
date:   2022-11-13 19:59:43 +0300
categories: jekyll update
---

**Contents**
* TOC
{:toc}
## CVE-2021-20294 - readelf

### Code

```c
////ACID: filedata, symtab, section, strtab, strtab_size
static void
print_dynamic_symbol (Filedata *filedata, unsigned long si,
		      Elf_Internal_Sym *symtab,
		      Elf_Internal_Shdr *section,
		      char *strtab, size_t strtab_size)
{
  const char *version_string;
  enum versioned_symbol_info sym_info;
  unsigned short vna_other;
  Elf_Internal_Sym *psym = symtab + si;
  
  printf ("%6ld: ", si);
  print_vma (psym->st_value, LONG_HEX);
  putchar (' ');
  print_vma (psym->st_size, DEC_5);
  printf (" %-7s", get_symbol_type (filedata, ELF_ST_TYPE (psym->st_info)));
  printf (" %-6s", get_symbol_binding (filedata, ELF_ST_BIND (psym->st_info)));
  if (filedata->file_header.e_ident[EI_OSABI] == ELFOSABI_SOLARIS)
    printf (" %-7s",  get_solaris_symbol_visibility (psym->st_other));
  else
    {
      unsigned int vis = ELF_ST_VISIBILITY (psym->st_other);

      printf (" %-7s", get_symbol_visibility (vis));
      /* Check to see if any other bits in the st_other field are set.
	 Note - displaying this information disrupts the layout of the
	 table being generated, but for the moment this case is very rare.  */
      if (psym->st_other ^ vis)
	printf (" [%s] ", get_symbol_other (filedata, psym->st_other ^ vis));
    }
  printf (" %4s ", get_symbol_index_type (filedata, psym->st_shndx));

  bfd_boolean is_valid = VALID_SYMBOL_NAME (strtab, strtab_size,
					    psym->st_name);
  const char * sstr = is_valid  ? strtab + psym->st_name : _("");

  version_string
    = get_symbol_version_string (filedata,
				 (section == NULL
				  || section->sh_type == SHT_DYNSYM),
				 strtab, strtab_size, si,
				 psym, &sym_info, &vna_other); //XENO: Lots of ACID in will yield ACID out
  
  int len_avail = 21;
  if (! do_wide && version_string != NULL) //XENO: do_wide is true iff -W option passed
    {
      char buffer[256];

      len_avail -= sprintf (buffer, "@%s", version_string);

      if (sym_info == symbol_undefined)
	len_avail -= sprintf (buffer," (%d)", vna_other);
      else if (sym_info != symbol_hidden)
	len_avail -= 1;
    }

  print_symbol (len_avail, sstr);
// ...
}

```

### Code Review

1. `printf("%-7s")` is being called. 
This format specifier means a *left* align of the output string (due to "-"), for up to 7 bytes. 

In a similar manner, "%+7s" would perform *right* alignment of 7 bytes (We can think of the "-" as negative alignment). 

Cool side notes:

Dot operation - `"%24.6s"`, states *precision*.
For strings it truncs the string after 6 bytes (not including the null byte).
For integers it represents the number of digits, and for floats the number of digits after the dot. 

Asterisk operation - `"%*d"`, which takes the alignment value as an extra format specifier (which can be supplied during runtime). 

Finally, the dollar operation - `"%2$d"`, states the order of the formatted value (like `'{2}:{1}'.format(last, first)` within python).


2. Buffer overflow due to `sprintf()` usage: 

```c
char buffer[256];
len_avail -= sprintf (buffer, "@%s", version_string);
```

We can fully control `version_string`, hence overflowing the 256-byte array `buffer`. 

### Patch

The following patch was made:

```c
-      char buffer[256];
+      char buffer[16];
 
-      len_avail -= sprintf (buffer, "@%s", version_string);
+      len_avail -= 1 + strlen (version_string);
```

So instead of counting the written bytes into the buffer, a call for `strlen()` is being made (also taking into account the null byte). 

1. Note - `len_avail` is defined as an `int`. 
In case we fully control `version_string`, we may do a trick and perform integer overflow, making `len_avail` negative. 

2. The second `sprintf` copies a maximal digit representation `(%d)` (2147483648), a space, 2 brackets, and null byte. Meaning a total of 14 bytes. The new size of the buffer is 16 bytes, so this fix is safe (at least BOF-wise). 


## CVE-2021-43579 - HTMLDOC

### Code

```c
////ACID: everything read from fp
static int                       /* O - 0 = success, -1 = fail */
image_load_bmp(image_t *img,     /* I - Image to load into */
               FILE    *fp,      /* I - File to read from */
               int     gray,     /* I - Grayscale image? */
               int     load_data)/* I - 1 = load image data, 0 = just info */
{
  int   info_size,	/* Size of info header */
        depth,		/* Depth of image (bits) */
        compression,	/* Type of compression */
        colors_used,	/* Number of colors used */
        x, y,		/* Looping vars */
        color,		/* Color of RLE pixel */
        count,		/* Number of times to repeat */
        temp,		/* Temporary color */
        align;		/* Alignment bytes */
        uchar bit,	/* Bit in image */
        byte;		/* Byte in image */
        uchar *ptr;	/* Pointer into pixels */
        uchar		colormap[256][4];/* Colormap */


  // Get the header...
  getc(fp);			/* Skip "BM" sync chars */
  getc(fp);
  read_dword(fp);		/* Skip size */
  read_word(fp);		/* Skip reserved stuff */
  read_word(fp);
  read_dword(fp);

  // Then the bitmap information...
  info_size        = (int)read_dword(fp);
  img->width       = read_long(fp);
  img->height      = read_long(fp);
  read_word(fp);
  depth            = read_word(fp);
  compression      = (int)read_dword(fp);
  read_dword(fp);
  read_long(fp);
  read_long(fp);
  colors_used      = (int)read_dword(fp);
  read_dword(fp);

  if (img->width <= 0 || img->width > 8192 || img->height <= 0 || img->height > 8192)
    return (-1);

  if (info_size > 40)
    for (info_size -= 40; info_size > 0; info_size --)
      getc(fp);

  // Get colormap...
  if (colors_used == 0 && depth <= 8)
    colors_used = 1 << depth;

  fread(colormap, (size_t)colors_used, 4, fp);

  // Setup image and buffers...
  img->depth = gray ? 1 : 3;

  // If this image is indexed and we are writing an encrypted PDF file, bump the use count so
  // we create an image object (Acrobat 6 bug workaround)
  if (depth <= 8 && Encryption)
    img->use ++;

  // Return now if we only need the dimensions...
  if (!load_data)
    return (0);

  img->pixels = (uchar *)malloc((size_t)(img->width * img->height * img->depth));
  if (img->pixels == NULL)
    return (-1);

  if (gray && depth <= 8)
  {
    // Convert colormap to grayscale...
    for (color = colors_used - 1; color >= 0; color --)
      colormap[color][0] = (colormap[color][2] * 31 +
                            colormap[color][1] * 61 +
                            colormap[color][0] * 8) / 100;
  }

  // Read the image data...
  color = 0;
  count = 0;
  align = 0;
  byte  = 0;
  temp  = 0;

  for (y = img->height - 1; y >= 0; y --)
  {
    ptr = img->pixels + y * img->width * img->depth;

    switch (depth)
    {
      case 1 : /* Bitmap */
          for (x = img->width, bit = 128; x > 0; x --)
	  {
	    if (bit == 128)
	      byte = (uchar)getc(fp);

	    if (byte & bit)
	    {
	      if (!gray)
	      {
		*ptr++ = colormap[1][2];
		*ptr++ = colormap[1][1];
              }

	      *ptr++ = colormap[1][0];
	    }
	    else
	    {
	      if (!gray)
	      {
		*ptr++ = colormap[0][2];
		*ptr++ = colormap[0][1];
	      }

	      *ptr++ = colormap[0][0];
	    }

	    if (bit > 1)
	      bit >>= 1;
	    else
	      bit = 128;
	  }

         /*
	  * Read remaining bytes to align to 32 bits...
	  */

	  for (temp = (img->width + 7) / 8; temp & 3; temp ++)
	    getc(fp);
          break;

      case 4 : /* 16-color */
          for (x = img->width, bit = 0xf0; x > 0; x --)
	  {
	   /*
	    * Get a new count as needed...
	    */

            if (compression != BI_RLE4 && count == 0)
	    {
	      count = 2;
	      color = -1;
            }

	    if (count == 0)
	    {
	      while (align > 0)
	      {
	        align --;
		getc(fp);
              }

	      if ((count = getc(fp)) == 0)
	      {
		if ((count = getc(fp)) == 0)
		{
		 /*
		  * End of line...
		  */

                  x ++;
		  continue;
		}
		else if (count == 1)
		{
		 /*
		  * End of image...
		  */

		  break;
		}
		else if (count == 2)
		{
		 /*
		  * Delta...
		  */

		  count = getc(fp) * getc(fp) * img->width;
		  color = 0;
		}
		else
		{
		 /*
		  * Absolute...
		  */

		  color = -1;
		  align = ((4 - (count & 3)) / 2) & 1;
		}
	      }
	      else
	        color = getc(fp);
            }

           /*
	    * Get a new color as needed...
	    */

	    count --;

            if (bit == 0xf0)
	    {
              if (color < 0)
		temp = getc(fp) & 255;
	      else
		temp = color;

             /*
	      * Copy the color value...
	      */

              if (!gray)
	      {
		*ptr++ = colormap[temp >> 4][2];
		*ptr++ = colormap[temp >> 4][1];
              }

	      *ptr++ = colormap[temp >> 4][0];
	      bit    = 0x0f;
            }
	    else
	    {
             /*
	      * Copy the color value...
	      */

	      if (!gray)
	      {
	        *ptr++ = colormap[temp & 15][2];
	        *ptr++ = colormap[temp & 15][1];
	      }

	      *ptr++ = colormap[temp & 15][0];
	      bit    = 0xf0;
	    }
	  }
          break;

      case 8 : /* 256-color */
          for (x = img->width; x > 0; x --)
	  {
	   /*
	    * Get a new count as needed...
	    */

            if (compression != BI_RLE8)
	    {
	      count = 1;
	      color = -1;
            }

	    if (count == 0)
	    {
	      while (align > 0)
	      {
	        align --;
		getc(fp);
              }

	      if ((count = getc(fp)) == 0)
	      {
		if ((count = getc(fp)) == 0)
		{
		 /*
		  * End of line...
		  */

                  x ++;
		  continue;
		}
		else if (count == 1)
		{
		 /*
		  * End of image...
		  */

		  break;
		}
		else if (count == 2)
		{
		 /*
		  * Delta...
		  */

		  count = getc(fp) * getc(fp) * img->width;
		  color = 0;
		}
		else
		{
		 /*
		  * Absolute...
		  */

		  color = -1;
		  align = (2 - (count & 1)) & 1;
		}
	      }
	      else
	        color = getc(fp);
            }

           /*
	    * Get a new color as needed...
	    */

            if (color < 0)
	      temp = getc(fp);
	    else
	      temp = color;

            count --;

           /*
	    * Copy the color value...
	    */

            if (!gray)
	    {
	      *ptr++ = colormap[temp][2];
	      *ptr++ = colormap[temp][1];
	    }

	    *ptr++ = colormap[temp][0];
	  }
          break;

      case 24 : /* 24-bit RGB */
          if (gray)
	  {
            for (x = img->width; x > 0; x --)
	    {
	      temp = getc(fp) * 8;
	      temp += getc(fp) * 61;
	      temp += getc(fp) * 31;
	      *ptr++ = (uchar)(temp / 100);
	    }
	  }
	  else
	  {
            for (x = img->width; x > 0; x --, ptr += 3)
	    {
	      ptr[2] = (uchar)getc(fp);
	      ptr[1] = (uchar)getc(fp);
	      ptr[0] = (uchar)getc(fp);
	    }
          }

         /*
	  * Read remaining bytes to align to 32 bits...
	  */

	  for (temp = img->width * 3; temp & 3; temp ++)
	    getc(fp);
          break;
    }
  }

  return (0);
}
```

### Code Review

1. `fread` stack buffer overflow:

```c
if (colors_used == 0 && depth <= 8)
    colors_used = 1 << depth;

fread(colormap, (size_t)colors_used, 4, fp);
```

The array is defined as `char colormap[256][4]` (1024 bytes long), and we fully control `int depth`. 

Because of `depth` check, the maximal size of `colors_used` is 256, and there is no trivial BOF.


However, note that `depth` is defined as an int. 

Therefore, if we set its value to negative value, the check will pass, while setting `colors_used` to our wish (the trick is that operator '<<' DO work with negative numbers). 

For example, by setting `depth == -22`, we would achieve `colors_used = 0x400`, hence creating a buffer overflow of `(0x400 * 4  - 1024)` bytes.

2. `img->pixels` heap buffer overflow:

```c
img->pixels = (uchar *)malloc((size_t)(img->width * img->height * img->depth));
  if (img->pixels == NULL)
    return (-1);
```

Since we control the `img` parameters, we may set one of these as `0`. 
The result of `malloc(0)` is unspecified, and usually *returns a pointer to length 0 buffer, instead of NULL* . 

The assignment is performed via the `ptr` variable. 

### Patch
The following patch was added:
```c
if (colors_used == 0 && depth <= 8)
    colors_used = 1 << depth;
else if (colors_used > 256)
    return -1

```

This patch is awful for many reasons. 

The first reason -  wrongly used `else if` - it should be checked in addition to the `if` block.

The second reason - `color_used` is defined as an `int` (instead of `uint`), and therefore the check may pass for negative values, while overflowing the buffer (due to the size_t cast).


## CVE-Unknown-SSBB-BH2021🇰🇷 - Exynos Baseband

### Code

```c

char ** find_tag_end(char **result) {
	char *i;
	unsigned int v2;
	unsigned int cur_char;
	for (i = *result ; ; ++i) {
		cur_char = (unsigned __int8)*i;
		if (cur_char <= 0xD && ((1 << cur_char) & 0x2601) != 0) // \0 \t \n \r
			break;
		v2 = cur_char - 32;
		if (v2 <= 0x1F && ((1 << v2) & (unsigned int)&unk_C0008001) != 0) // space / > ?
			break;
	}
	*result = i;
	return result;
}

int IMSPL_XmlGetNextTagName(char *src, char *dst){
	char * ptr = src;
	// The cut code will:
	// 1. Skip space characters
	// 2. Find the beginning mark '<'
	// 3. Skip comments
	// ...
	char * v8 = ptr + 1;
	char ** v13;
	v13[0] = v8;
	find_tag_end((char **)v13);
	v9 = v13[0];
	if (v8 != v13[0]) {
		memcpy(dst, (int *) ((char *)ptr + 1), v13[0] - v8);
		dst[v9 - v8] = 0;
		V12 = 10601;
		// IMSPL_XmiGetNextTagName: Tag name
		v11 = &log_struct_437f227c;
		Logs((int *)&v11, (int)dst, -1, -20071784);
		* (unsigned __int8 **)src = v13[0];
		LOBYTE(result) = 1;
		return (unsigned __int8) result;
	}
	// ...
}
int IMSPL_XmlParser_ContactLstDecode(int *a1, int *a2) {
	unsigned __int8 *v4;
	int v5;
	log_info_s *v7;
	int v8;
	unsigned __int8 *v9;
	int v10;
	char v11[136];

	bzero(v11, 100);
	v10 = 0;
	v4 = (unsigned __int8 *)*a1;
	v8 = 10597;
	v9 = v4;
	// ----------%s----------
	v7 = &log_struct_4380937c;
	log_0x418ffa6c(&v7, "IMSPL_XmlParser_ContactLstDecode", -20071784) ;
	if (IMSPL_XmlGetNextTagName((char *)&v9, v11) ! = 1) {
	LABEL_8:
		*a1 = (int)v9;
		v8 = 10597;
		// Function END
		v7 = &log_struct_43809448;
		log_0x418ffa6c(&v7, -20071784) ;
		return 1;
	}
// ...
}
```

### Code Review

1. `bzero` only zeros out the first 100 bytes of the array `v11`, instead of all of its 136 bytes.

2. Stack buffer overflow: 

Right after the comments of `IMSPL_XmlGetNextTagName`, `ptr` points towards the first `'<'`, and `v13` towards the tag inner content.

After those variables are set, `find_tag_end` is called - to find the corresponding `'>'`. It updates the result within `v13[0]`. 

```c
	find_tag_end((char **)v13);
	v9 = v13[0];
	if (v8 != v13[0]) {
		memcpy(dst, (int *) ((char *)ptr + 1), v13[0] - v8);
		dst[v9 - v8] = 0;
```

Over controlled input - we control the value of `v13[0]`, as we may enter a very long tag name: `<AAAAA...A>`. 
In such case, the length of the copied buffer (`v13[0] - v8`) is controlled, while the `dst` buffer size is constant 136 bytes.

### Patch

None posted yet, lol. 


## CVE-2022-0435 - Linux Kernel TIPC

Transparent inter-Process Communication protocol - for IPC over the network. 

### Code

```c

/* struct tipc_peer: state of a peer node and its domain
 * @addr: tipc node identity of peer
 * @head_map: shows which other nodes currently consider peer 'up'
 * @domain: most recent domain record from peer
 * @hash: position in hashed lookup list
 * @list: position in linked list, in circular ascending order by 'addr'
 * @applied: number of reported domain members applied on this monitor list
 * @is_up: peer is up as seen from this node
 * @is_head: peer is assigned domain head as seen from this node
 * @is_local: peer is in local domain and should be continuously monitored
 * @down_cnt: - numbers of other peers which have reported this on lost
 */
struct tipc_peer {
	u32 addr;
	struct tipc_mon_domain *domain;
	struct hlist_node hash;
	struct list_head list;
	u8 applied;
	u8 down_cnt;
	bool is_up;
	bool is_head;
	bool is_local;
};

/* struct tipc_mon_domain: domain record to be transferred between peers
 * @len: actual size of domain record
 * @gen: current generation of sender's domain
 * @ack_gen: most recent generation of self's domain acked by peer
 * @member_cnt: number of domain member nodes described in this record
 * @up_map: bit map indicating which of the members the sender considers up
 * @members: identity of the domain members
 */
struct tipc_mon_domain {
	u16 len;
	u16 gen;
	u16 ack_gen;
	u16 member_cnt;
	u64 up_map;
	u32 members[MAX_MON_DOMAIN];
};

#define MAX_MON_DOMAIN       64

static int dom_rec_len(struct tipc_mon_domain *dom, u16 mcnt)
{
	return ((void *)&dom->members - (void *)dom) + (mcnt * sizeof(u32));
}

/* tipc_mon_rcv - process monitor domain event message
 */
// ACID: *data, dlen
void tipc_mon_rcv(struct net *net, void *data, u16 dlen, u32 addr,
		  struct tipc_mon_state *state, int bearer_id)
{
	struct tipc_monitor *mon = tipc_monitor(net, bearer_id);
	struct tipc_mon_domain *arrv_dom = data;
	struct tipc_mon_domain dom_bef;
	struct tipc_mon_domain *dom;
	struct tipc_peer *peer;
	u16 new_member_cnt = ntohs(arrv_dom->member_cnt);
	int new_dlen = dom_rec_len(arrv_dom, new_member_cnt);
	u16 new_gen = ntohs(arrv_dom->gen);
	u16 acked_gen = ntohs(arrv_dom->ack_gen);
	bool probing = state->probing;
	int i, applied_bef;

	state->probing = false;

	/* Sanity check received domain record */
	if (dlen < dom_rec_len(arrv_dom, 0))
		return;
	if (dlen != dom_rec_len(arrv_dom, new_member_cnt))
		return;
	if ((dlen < new_dlen) || ntohs(arrv_dom->len) != new_dlen)
		return;

	/* Synch generation numbers with peer if link just came up */
	if (!state->synched) {
		state->peer_gen = new_gen - 1;
		state->acked_gen = acked_gen;
		state->synched = true;
	}

	if (more(acked_gen, state->acked_gen))
		state->acked_gen = acked_gen;

	/* Drop duplicate unless we are waiting for a probe response */
	if (!more(new_gen, state->peer_gen) && !probing)
		return;

	write_lock_bh(&mon->lock);
	peer = get_peer(mon, addr);
	if (!peer || !peer->is_up)
		goto exit;

	/* Peer is confirmed, stop any ongoing probing */
	peer->down_cnt = 0;

	/* Task is done for duplicate record */
	if (!more(new_gen, state->peer_gen))
		goto exit;

	state->peer_gen = new_gen;

	/* Cache current domain record for later use */
	dom_bef.member_cnt = 0;
	dom = peer->domain;
	if (dom)
		memcpy(&dom_bef, dom, dom->len);

	/* Transform and store received domain record */
	if (!dom || (dom->len < new_dlen)) {
		kfree(dom);
		dom = kmalloc(new_dlen, GFP_ATOMIC);
		peer->domain = dom;
		if (!dom)
			goto exit;
	}
	dom->len = new_dlen;
	dom->gen = new_gen;
	dom->member_cnt = new_member_cnt;
	dom->up_map = be64_to_cpu(arrv_dom->up_map);
	for (i = 0; i < new_member_cnt; i++)
		dom->members[i] = ntohl(arrv_dom->members[i]);

	/* Update peers affected by this domain record */
	applied_bef = peer->applied;
	mon_apply_domain(mon, peer);
	mon_identify_lost_members(peer, &dom_bef, applied_bef);
	mon_assign_roles(mon, peer_head(peer));
exit:
	write_unlock_bh(&mon->lock);
}
```

### Code Review

1. We control `dlen` parameter, which is defined as a `uint16_t`. 
This value seems abit low, so there might be an integer overflow for inputs greater than `2^16`. 

2. `arrv_dom` contains a `len` attirbute of `uint16_t`, as well as `members` static array, of total length `4 * 64 = 256` bytes.

3. `new_dlen` is calculated by `dom_rec_len`, which returns the offset a new member will be written to within the struct.

4. Integer underflow:

```c
state->peer_gen = new_gen - 1;
```

No value check is performed. 
We fully control `new_gen`, and may set it to 0 - to perform integer underflow for `peer_gen`. 

5. The following `memcpy` seems yummy, however its exploitation isn't trivial:

```c
/* Cache current domain record for later use */
	dom_bef.member_cnt = 0;
	dom = peer->domain;
	if (dom)
		memcpy(&dom_bef, dom, dom->len);
```

`dom` is determined by `peer`, which we cannot control - as it initiated by `mon` and `addr` - both parameters we have no control of.

6. Stack buffer overflow:

```c
for (i = 0; i < new_member_cnt; i++)
		dom->members[i] = ntohl(arrv_dom->members[i]);
```

As previously stated, the `members` array is a static array of 64 elements. 
There are very few sanity checks:

```c
/* Sanity check received domain record */
	if (dlen < dom_rec_len(arrv_dom, 0))
		return;
	if (dlen != dom_rec_len(arrv_dom, new_member_cnt))
		return;
	if ((dlen < new_dlen) || ntohs(arrv_dom->len) != new_dlen)
		return;
```

And Since `new_members_cnt` and `dlen` are controlled by user input, it seems like an overflow may occur.
(We may insert a large value of `new_member_cnt`, and match it with corresponding large `dlen` to bypass the sanities). 

However - note this snippet is *actually safe* - the `kmalloc(new_dlen)` call allocates the right amount of extra bytes!
It still lets us fully control the content of `dom`. 


7. The `kmalloc` snippet is triggered only for the first time:

```c
if (!dom || (dom->len < new_dlen)) {
		kfree(dom);
		dom = kmalloc(new_dlen, GFP_ATOMIC);
		peer->domain = dom;
		if (!dom)
			goto exit;
```

So after a single trigger of this flow (cached packet) - we may control the `peer->domain` (`dom`), which is used by the naive `memcpy` call (5).

Because we can specifically control `dom->len`, a trivial stack buffer overflow occurs. 

### Patch

Not stated.


## CVE-2020-10005 - macOS SMB

### Code

```c
undefined8
smb2::extract(uchar **pkt_ptr_ptr,uchar **packet_size_hdr_ptr_ptr,tree_connect_request *memcpy_src,
             uchar **smb_hdr_ptr_ptr)

{
  short *psVar1;
  undefined8 uVar2;
  short *packetEnd;
  ushort tc_PathLength;
  ushort tc_PathOffset;
  short tc_StructureSize;
  
  psVar1 = (short *)*pkt_ptr_ptr;
  if (7 < (long)*packet_size_hdr_ptr_ptr - (long)psVar1) {
    tc_StructureSize = *psVar1;
    *pkt_ptr_ptr = (uchar *)(psVar1 + 1);
    memcpy_src->short_1_StructureSize = tc_StructureSize;
    if (tc_StructureSize == 9) {
      *pkt_ptr_ptr = (uchar *)(psVar1 + 2);
      memcpy_src->short_2_Flags = 0;
      tc_PathOffset = psVar1[2];
      *pkt_ptr_ptr = (uchar *)(psVar1 + 3);
      memcpy_src->short_3_PathOffset = tc_PathOffset;
      tc_PathLength = psVar1[3];
      *pkt_ptr_ptr = (uchar *)(psVar1 + 4);
      memcpy_src->short_4_PathLength = tc_PathLength;
      packetEnd = (short *)(*smb_hdr_ptr_ptr + tc_PathOffset +
                           ((uint)(*smb_hdr_ptr_ptr + tc_PathOffset) & 1));
      *pkt_ptr_ptr = (uchar *)packetEnd;
      if ((psVar1 <= packetEnd) && (psVar1 = (short *)*packet_size_hdr_ptr_ptr, packetEnd <= psVar1)
         ) {
        packetEnd = (short *)((long)packetEnd + (ulong)tc_PathLength);
        if (psVar1 <= packetEnd) {
          packetEnd = psVar1;
        }
        uVar2 = smb::extract_utf16_string
                          (pkt_ptr_ptr,(uchar *)packetEnd,(oem_string *)&memcpy_src->buf);
        return uVar2;
      }
    }
  }
  return 0;
}

////ACID: in_packet_ptr, in_packet_size
ulong smb2_dispatch_tree_connect(smb_request *param_1, uchar *in_packet_ptr, uchar *in_packet_size)
{
  int *piVar1;
  void **this;
  long lVar2;
  char cVar4;
  ulong num_chars;
  undefined8 uVar6;
  ulong uVar7;
  byte bVar8;
  void *lVar9;
  uint bitmasked_num_chars;
  uchar *local_8b8;
  uchar *local_8b0;
  uchar *packet_input_ptr;
  uchar *packet_size;
  unknown_struct_1 local_898;
  undefined4 uStack2188;
  int local_87c;
  undefined4 local_878;
  uint uStack2164;
  undefined2 local_870;
  undefined2 local_86e;
  undefined2 uStack2156;
  uint local_86a;
  wchar16 wcSharePath [1024];
  tree_connect_request memcpy_src;
  undefined8 local_48;
  long local_38;
  long lVar3;
  uchar *puVar2;
  
  local_38 = *(long *)__got::___stack_chk_guard;
  memcpy_src = ZEXT816(0);
  local_48 = 0;
  local_87c = 0;
  _local_898 = ZEXT816(0);
  packet_input_ptr = in_packet_ptr;
  packet_size = in_packet_size;
  __stubs::___bzero(wcSharePath,0x800);
  cVar4 = smb2::extract(&packet_input_ptr,&packet_size,&memcpy_src,(uchar **)(param_1 + 9));
  num_chars = 1;
  if (cVar4 == '\0') goto fail1;
  local_898 = CONCAT48((uint)local_48,local_898.0_8_buf_ptr);
  _local_898 = CONCAT88(stack0xfffffffffffff770,memcpy_src.buf);
  if (memcpy_src.buf == (void *)0x0) {
fail2:
    uVar6 = platform::log::smbx_std_log();
    cVar4 = __stubs::_os_log_type_enabled(uVar6,0x10);
    if (cVar4 != '\0') {
      local_878 = 0x8200102;
      uStack2164 = 0x8f914;
      local_870 = 1;
      local_86e = 0;
      __stubs::__os_log_impl(0x100000000,uVar6,0x10,"%s: bad path for tree connect",&local_878,0xc);
    }
    bitmasked_num_chars = 0xc00000be;
  }
  else {
    bitmasked_num_chars = (uint)local_48 & 0x3fffffff;
    num_chars = (ulong)bitmasked_num_chars;
    if ((local_898 & (undefined  [12])0x3fffffff) == (undefined  [12])0x0) goto fail2;
      if ((int)(uint)local_48 < 0) {
        if (*(short *)((long)memcpy_src.buf + num_chars * 2 + -2) != 0) goto memcpy_path;
      }
      else if (*(short *)(num_chars * 2 + -2) != 0) {
        memcpy_src.buf = (void *)0x0;
memcpy_path:
        __stubs::_memcpy(wcSharePath,memcpy_src.buf,num_chars * 2);
        wcSharePath[num_chars] = L'\0';
        local_898 = CONCAT48(bitmasked_num_chars + 0x80000000,wcSharePath);
      }
      bitmasked_num_chars = connect_to_named_tree(param_1,(oem_string *)&local_898,&local_87c);
      if (bitmasked_num_chars < 0x40000000) {
        *(int *)¶m_1[6].PathOffset = local_87c;
        smb_session::find_tree((int)register0x00000020 + -0x878);
        lVar2 = *(long *)(param_1 + 10);
        lVar3 = CONCAT44(uStack2164,local_878);
        *(long *)(param_1 + 10) = lVar3;
        if (lVar3 != 0) {
          LOCK();
          *(int *)(lVar3 + 0x10) = *(int *)(lVar3 + 0x10) + 1;
        }
        ///...
      }
  }
}
```

### Code Review

1. `wcSharePath` is a static array of 1024 bytes. 

2. We fully control `extract` first two parameters. This function fills the buffer `memcpy_src.buf`, which later on serves as a source for memcpy.

Therefore, we control `tc_PathOffset` value, which in turn may lead to huge `packetEnd` value. 
A possible buffer overflow may occur, depending on `extract_utf16_string` implementation. 

```c
uVar2 = smb::extract_utf16_string(pkt_ptr_ptr,(uchar *)packetEnd,(oem_string *)&memcpy_src->buf);
```

Anyways, the content of `memcpy_src->buf` is fully determined by the input.

3. The stack buffer overflow:

```c
memcpy_path:
        __stubs::_memcpy(wcSharePath,memcpy_src.buf,num_chars * 2);
        wcSharePath[num_chars] = L'\0';
```

Note - `bitmasked_num_chars` is input controlled, hence the overflow.

### Patch

The following check was added:

```c
if (bitmasked_num_chars < 0x155)
{...}
``` 

## CVE-2021-21574 - UEFI BIOS

[video][uefi_bios_video]

Dell laptopts have a BIOS that implements UEFI. 

This BIOS have a feature to support remote BIOS update. 

The dell firmware access to `*.dell.com` via SSL, and pulls down an XML file (`CatalogBc.xml`). 

All of CVE-2021-2157(1-4) are published vulns for this remote patch capability. 

### Code

```c
// Pseudocode derived from assembly
idx = 0
write_ptr = buf_on_stack; //rbp-0x158
while(1) {
    if ( idx >= strnlen(hex_ptr, 20000) )
        break;

    *write_ptr++ = CONVERT_HEX(hex_ptr[idx]) << 4 | 
                   CONVERT_HEX(hex_ptr[idx+1]);
    idx += 2;
}
if ( buf_on_stack != calculated_sha256 ) {
	if ( memcmp(buf_on_stack, calculated_sha256, 32) )
		retval = EFI_NOT_FOUND;
	}
}
```

### Code Review

1. Note we control the input `hex_ptr`. 

We also note `write_ptr` is a buffer allocated by 0x158 bytes on the stack. 

2. `strnlen` actually returns the minimum of `strlen(s)` and `n`. 

3. Stack buffer overflow:

```c
*write_ptr++ = CONVERT_HEX(hex_ptr[idx]) << 4 | 
                   CONVERT_HEX(hex_ptr[idx+1]);
```

Every two bytes of the input hex string, are converted to raw byte.
However - note `idx` grows to `min(strlen(hex_ptr), 20000)`. 

So as long as `strlen(hex_ptr) > 0x158`, an overflow occurs.
Just enter a long string, without any `\x00` within its first bytes.


### Patch

Proprietary code. 
We dont know :/ 


## CVE-2018-9312

### Code

```c
char filename[1024];

memset(filename, 0, 0x400);
sprintf(filename, "%s/%s", basePath, metadata->decompressedFileName);
```

### Code Review

1. Trivial overflow on `sprintf` - no check is being made on any of the format parameters. 


### Patch

None


## Fortify Source

`-D_FORTIFY_SOURCE=1` adds compile-time checks for buffer overflows within the code.

It affects `memcpy, mempcpy, memove, memset, strncat, snprintf, strncpy` and many more.

`-DFORTIFY_SOURCE=2` adds runtime checks, in addition to the compile-time checks. 
These functions are suffied with `_chk`. 

Post glibc2.23, `-DFORTIFY_SOURCE=3` was added - and can catch even more vulns. 

It is recommended to add this within production environment. 

## ASan, KASan

Address Sanitizer, and its equivalent kernel tool.
Makes some drastic compile-time changes, in order to add both compile-time and runtime memory errors detection.

For instance, it actually wraps `malloc()` calls within a more sophisticated mechanism, that keeps track of allocated memory (resembles dynamic binary instrumentation).

Its main usages are within debug / QA builds, not for production. 
Very usefull to use ASan + Fuzzer (such as AFL). 
For gcc, it can be trigged via `-fsanitize=address`. 

Detailed ASan guides: [link1][gcc-instrumentation] [link2][google-asan]

Interesting CVEs found via ASan + fuzzer (all found by Talos team):

```bash
CVE-2021-21811 
CVE-2017-2816 
CVE-2020-28596 
CVE-2020-13524 
CVE-2019-5051 
CVE-2021-30522 
```

Detailed found vulnerabilities:
[link][talos-vuln] and [link][tbone-vuln].

Note: ASan doesn't work well with `FORTIFY_SOURCE`. 

## Extra CVEs For Learning

```bash
CVE-2021-31321
CVE-2021-33833
CVE-2020-27347
CVE-2021-30628
CVE-2021-28972
CVE-2021-21748
CVE-2021-21149
CVE-2021-3064
CVE-2020-16898
```

And [this][blackhat-stack].

[uefi_bios_video]: https://www.youtube.com/watch?v=qxWfkSonK7M&ab_channel=DEFCONConference
[gcc-instrumentation]: https://gcc.gnu.org/onlinedocs/gcc/Instrumentation-Options.html
[google-asan]: https://github.com/google/sanitizers/wiki/AddressSanitizer#using-addresssanitizer
[talos-vuln]: https://talosintelligence.com/vulnerability_reports/TALOS-2021-1297
[tbone-vuln]: https://kunnamon.io/tbone/tbone-v1.0-redacted.pdf
[blackhat-stack]: https://i.blackhat.com/USA-20/Wednesday/us-20-Buhren-All-You-Ever-Wanted-To-Know-About-The-AMD-Platform-Security-Processor-And-Were-Afraid-To-Emulate.pdf
