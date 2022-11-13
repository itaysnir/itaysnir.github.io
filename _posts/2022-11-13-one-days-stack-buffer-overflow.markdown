---
layout: post
title:  "One Days - Stack Buffer Overflows"
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

### Code
