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

1. A printf("%-7s") is being called. This format specifier meaning is *left* align the output string (due to "-") for up to 7 bytes. 
In a similar manner, "%+7s" would perform *right* alignment of 7 bytes. We can think of the "-" as negative alignment. 

Cool side notes - 
Advanced usage of format specifiers includes the dot operation - `"%24.6s"`, which states *precision* (For strings: truncs the string after 6 bytes, not including the null byte. For integers: number of digits). 
As well as the asterisk operation - `"%*d"`, which takes the alignment value as an extra format specifier (which can be supplied during runtime). 
Finally, the dollar operation - `"%2$d"`, states the order of the formatted value (like `'{2}:{1}'.format(last, first)` within python).

2. Buffer overflow due to `sprintf()` usage : 
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

2. The second `sprintf` copies a maximal digit representation `(%d)` (2147483648), a space, 2 brackets, and null byte. Meaning a total of 14 bytes. The new size of the buffer is 16 bytes, so this fix is safe (BOF-wise). 

## CVE-2021-43579 
