---
layout: post
title:  "One Days - Other Integer Issues"
date:   2022-11-20 20:00:01 +0300
categories: jekyll update
---

**Contents**
* TOC
{:toc}
## Background

### Incorrect signed sanity checks

Trivial example:

```c
int size = strtoul(argv[1], NULL, 16);
if (size > 100)
{
    printf("Nice try\n");
    return;
}

memcpy(buf, argv[2], size);
```

Of course, this is bypass-able as attacker enters a negative value. `memcpy` treats the `size` variable as an unsigned integer, hence producing overflow. 


### Integer Truncation

```c
unsigned int size ;
...
unsigned short alloc_size = size;  // stores only the lowest 2 bytes
```

Allocation via `size = 0x10000` would lead to `alloc_size = 0`. 


### Signed Integer Extensions 

Holds for signed integers. 

```c
char buf[0x10000];
char *ptr1;
short size1 = 0x8000;

ptr1 = buf + size1;  // Actually DECREASES by 0x8000 bytes!
```

Since the MSB is '1', the signed integer actually represents a negative number. 

Hence, it will actually perform an OOB-underflow!


## CVE-2019-15948 - TI Bluetooth


### Code

```c
////ACID: where ptr_ll_pkt points after assignment
// Pseudocode from Ghidra decompilation
void process_adv_ind_pdu(int ptr_some_struct)
{
  byte bVar1;
  byte ll_len;
  uint n;
  uint uVar2;
  byte *ptr_ll_pkt;
  undefined local_40;
  byte local_3f;
  undefined auStack62 [0x6];
  undefined local_38;
  undefined stack_buffer [0x1f];
  undefined local_18;

  ptr_ll_pkt = (byte *)(DAT_0005b528 + (uint)*(ushort *)(ptr_some_struct + 0x8));
  bVar1 = *ptr_ll_pkt;
  ll_len = ptr_ll_pkt[0x1];
  uVar2 = (uint)bVar1 & 0xf;
  local_3f = (byte)(((uint)bVar1 << 0x19) >> 0x1f);
  FUN_00067554(auStack62,ptr_ll_pkt + 0x2,0x6);
  n = ((uint)ll_len & 0x3f) - 0x6 & 0xff;
  local_38 = (undefined)n;
  memcpy(stack_buffer,ptr_ll_pkt + 0x8,n);
  local_18 = *(undefined *)(ptr_some_struct + 0xa);
  if ((bVar1 & 0xf) == 0x0) {
    local_40 = 0x0;
  }
  else {
    if (uVar2 == 0x1) {
      local_40 = 0x1;
      local_38 = 0x0;
    }
    else {
      if (uVar2 == 0x2) {
        local_40 = 0x3;
      }
      else {
        if (uVar2 != 0x6) {
          return;
        }
        local_40 = 0x2;
      }
    }
  }
  FUN_000398e2(0x1,&local_40);
  return;
}
```

### Code Review

1. `n` is correctly defined as an uint. 

However, its calculation enables a value as large as 0xff bytes:

```c
n = ((uint)ll_len & 0x3f) - 0x6 & 0xff;
```

Since `ll_len` is attacker controlled, it may be set to 5, which would underflow, and due to truncation `n` would be set to 0xff bytes.

2. Stack buffer overflow:

```c
memcpy(stack_buffer,ptr_ll_pkt + 0x8,n);
```

Since `stack_buffer` is only 0x1f bytes long, a value of `n = 0xff` enables a stack overflow. 

### Patch

No released patch.


## CVE-2019-14196 - u-boot NFS

### Code

```c
// Globals
static char filefh[NFS3_FHSIZE]; /* NFSv2 / NFSv3 file handle */
static int filefh3_length;	/* (variable) length of filefh when NFSv3 */

////ACID: pkt
static int nfs_lookup_reply(uchar *pkt, unsigned len)
{
	struct rpc_t rpc_pkt;

	debug("%s\n", __func__);

	memcpy(&rpc_pkt.u.data[0], pkt, len);

// ...

	if (supported_nfs_versions & NFSV2_FLAG) {
		memcpy(filefh, rpc_pkt.u.reply.data + 1, NFS_FHSIZE);
	} else {  /* NFSV3_FLAG */
		filefh3_length = ntohl(rpc_pkt.u.reply.data[1]);
		if (filefh3_length > NFS3_FHSIZE)
			filefh3_length  = NFS3_FHSIZE;
		memcpy(filefh, rpc_pkt.u.reply.data + 2, filefh3_length);
	}

	return 0;
}
```

### Code Review

1. Only `pkt` is attacker-controlled. 

This means `rpc_pkt.u.data` is controlled.

2. `filefh3_length` defined as a static int, instead of uint. 
Moreover, it is attacker controlled. 

There is an insufficient sanity check:

```c
if (filefh3_length > NFS3_FHSIZE)
	filefh3_length  = NFS3_FHSIZE;
```

As `filefh3_length` might be set to some negative value, hence bypassing the sanity check.

3. Since `memcpy` takes an uint argument, a `.BSS` buffer overflow occurs for negative inputs.

### Patch

The fixes weren't really fixing anything. 


## CVE-2020-15999 - Chrome PNG Parser

### Code

```c
#if CHAR_BIT == 8 && UCHAR_MAX == 255
   typedef unsigned char png_byte;
#else
#  error "libpng requires 8-bit bytes"
#endif

typedef char  FT_String;
typedef unsigned char  FT_Byte;
typedef signed char  FT_Char;
typedef unsigned char  FT_Bool;
typedef signed short  FT_FWord;   /* distance in FUnits */
typedef unsigned short  FT_UFWord;  /* unsigned distance */
typedef signed short  FT_Short;
typedef unsigned short  FT_UShort;
typedef signed int  FT_Int;
typedef unsigned int  FT_UInt;
typedef signed long  FT_Long;
typedef unsigned long  FT_ULong;

typedef struct  FT_Bitmap_
{
  unsigned int    rows;
  unsigned int    width;
  int             pitch;
  unsigned char*  buffer;
  unsigned short  num_grays;
  unsigned char   pixel_mode;
  unsigned char   palette_mode;
  void*           palette;
} FT_Bitmap;

typedef struct  TT_SBit_MetricsRec_
{
  FT_UShort  height;
  FT_UShort  width;

  FT_Short   horiBearingX;
  FT_Short   horiBearingY;
  FT_UShort  horiAdvance;

  FT_Short   vertBearingX;
  FT_Short   vertBearingY;
  FT_UShort  vertAdvance;

} TT_SBit_MetricsRec, *TT_SBit_Metrics;

////ACID: data, png_len
  FT_LOCAL_DEF( FT_Error )
  Load_SBit_Png( FT_GlyphSlot     slot,
                 FT_Int           x_offset,
                 FT_Int           y_offset,
                 FT_Int           pix_bits,
                 TT_SBit_Metrics  metrics,
                 FT_Memory        memory,
                 FT_Byte*         data,
                 FT_UInt          png_len,
                 FT_Bool          populate_map_and_metrics, //KC: Assume true
                 FT_Bool          metrics_only )
  {
    FT_Bitmap    *map   = &slot->bitmap;
    FT_Error      error = FT_Err_Ok;
    FT_StreamRec  stream;

    png_structp  png;
    png_infop    info;
    png_uint_32  imgWidth, imgHeight;
    int         bitdepth, color_type, interlace;
    FT_Int      i;
    png_byte*  *rows = NULL; /* pacify compiler */

    // ...

    FT_Stream_OpenMemory( &stream, data, png_len ); //KC: data ACID-> stream

    png = png_create_read_struct( PNG_LIBPNG_VER_STRING,
                                  &error,
                                  error_callback,
                                  warning_callback );

    // ...

    png_set_read_fn( png, &stream, read_data_from_FT_Stream ); //KC: stream ACID-> png

    png_read_info( png, info );
    png_get_IHDR( png, info,
                  &imgWidth, &imgHeight,
                  &bitdepth, &color_type, &interlace,
                  NULL, NULL );

    if ( error                                    ||
         ( !populate_map_and_metrics              &&
           ( (FT_Int)imgWidth  != metrics->width  ||
             (FT_Int)imgHeight != metrics->height ) ) )
      goto DestroyExit;

    if ( populate_map_and_metrics )
    {
      metrics->width  = (FT_UShort)imgWidth;
      metrics->height = (FT_UShort)imgHeight;

      map->width      = metrics->width;
      map->rows       = metrics->height;
      map->pixel_mode = FT_PIXEL_MODE_BGRA;
      map->pitch      = (int)( map->width * 4 );
      map->num_grays  = 256;

      /* reject too large bitmaps similarly to the rasterizer */
      if ( map->rows > 0x7FFF || map->width > 0x7FFF )
      {
        error = FT_THROW( Array_Too_Large );
        goto DestroyExit;
      }
    }

    // ...

    if ( populate_map_and_metrics )
    {
      /* this doesn't overflow: 0x7FFF * 0x7FFF * 4 < 2^32 */
      FT_ULong  size = map->rows * (FT_ULong)map->pitch;


      error = ft_glyphslot_alloc_bitmap( slot, size );
      if ( error )
        goto DestroyExit;
    }

    if ( FT_NEW_ARRAY( rows, imgHeight ) ) //KC: realloc(rows, imgHeight*sizeof(ptr))
    {                                      //KC: and memset() to 0
      error = FT_THROW( Out_Of_Memory );
      goto DestroyExit;
    }

    for ( i = 0; i < (FT_Int)imgHeight; i++ )
      rows[i] = map->buffer + ( y_offset + i ) * map->pitch + x_offset * 4;

    png_read_image( png, rows ); //KC: Uses the same imgWidth/Height from png_get_IHDR() to read the PNG into rows[]
  }

/* Pointers to pointers; i.e. arrays */
typedef png_byte        * * png_bytepp;

struct png_struct_def
{
#ifdef PNG_SETJMP_SUPPORTED
   jmp_buf jmp_buf_local;     /* New name in 1.6.0 for jmp_buf in png_struct */
   png_longjmp_ptr longjmp_fn;/* setjmp non-local goto function. */
   jmp_buf *jmp_buf_ptr;      /* passed to longjmp_fn */
   size_t jmp_buf_size;       /* size of the above, if allocated */
#endif
   png_error_ptr error_fn;    /* function for printing errors and aborting */
#ifdef PNG_WARNINGS_SUPPORTED
   png_error_ptr warning_fn;  /* function for printing warnings */
#endif
   png_voidp error_ptr;       /* user supplied struct for error functions */
   png_rw_ptr write_data_fn;  /* function for writing output data */
   png_rw_ptr read_data_fn;   /* function for reading input data */
   png_voidp io_ptr;          /* ptr to application struct for I/O functions */

#ifdef PNG_READ_USER_TRANSFORM_SUPPORTED
   png_user_transform_ptr read_user_transform_fn; /* user read transform */
#endif

#ifdef PNG_WRITE_USER_TRANSFORM_SUPPORTED
   png_user_transform_ptr write_user_transform_fn; /* user write transform */
#endif

/* These were added in libpng-1.0.2 */
#ifdef PNG_USER_TRANSFORM_PTR_SUPPORTED
#if defined(PNG_READ_USER_TRANSFORM_SUPPORTED) || \
    defined(PNG_WRITE_USER_TRANSFORM_SUPPORTED)
   png_voidp user_transform_ptr; /* user supplied struct for user transform */
   png_byte user_transform_depth;    /* bit depth of user transformed pixels */
   png_byte user_transform_channels; /* channels in user transformed pixels */
#endif
#endif

   png_uint_32 mode;          /* tells us where we are in the PNG file */
   png_uint_32 flags;         /* flags indicating various things to libpng */
   png_uint_32 transformations; /* which transformations to perform */

   png_uint_32 zowner;        /* ID (chunk type) of zstream owner, 0 if none */
   z_stream    zstream;       /* decompression structure */

#ifdef PNG_WRITE_SUPPORTED
   png_compression_bufferp zbuffer_list; /* Created on demand during write */
   uInt                    zbuffer_size; /* size of the actual buffer */

   int zlib_level;            /* holds zlib compression level */
   int zlib_method;           /* holds zlib compression method */
   int zlib_window_bits;      /* holds zlib compression window bits */
   int zlib_mem_level;        /* holds zlib compression memory level */
   int zlib_strategy;         /* holds zlib compression strategy */
#endif
/* Added at libpng 1.5.4 */
#ifdef PNG_WRITE_CUSTOMIZE_ZTXT_COMPRESSION_SUPPORTED
   int zlib_text_level;            /* holds zlib compression level */
   int zlib_text_method;           /* holds zlib compression method */
   int zlib_text_window_bits;      /* holds zlib compression window bits */
   int zlib_text_mem_level;        /* holds zlib compression memory level */
   int zlib_text_strategy;         /* holds zlib compression strategy */
#endif
/* End of material added at libpng 1.5.4 */
/* Added at libpng 1.6.0 */
#ifdef PNG_WRITE_SUPPORTED
   int zlib_set_level;        /* Actual values set into the zstream on write */
   int zlib_set_method;
   int zlib_set_window_bits;
   int zlib_set_mem_level;
   int zlib_set_strategy;
#endif

   png_uint_32 width;         /* width of image in pixels */
   png_uint_32 height;        /* height of image in pixels */
   png_uint_32 num_rows;      /* number of rows in current pass */
   png_uint_32 usr_width;     /* width of row at start of write */
   size_t rowbytes;           /* size of row in bytes */
   png_uint_32 iwidth;        /* width of current interlaced row in pixels */
   png_uint_32 row_number;    /* current row in interlace pass */
   png_uint_32 chunk_name;    /* PNG_CHUNK() id of current chunk */
   png_bytep prev_row;        /* buffer to save previous (unfiltered) row.
                               * While reading this is a pointer into
                               * big_prev_row; while writing it is separately
                               * allocated if needed.
                               */
   png_bytep row_buf;         /* buffer to save current (unfiltered) row.
                               * While reading, this is a pointer into
                               * big_row_buf; while writing it is separately
                               * allocated.
                               */
#ifdef PNG_WRITE_FILTER_SUPPORTED
   png_bytep try_row;    /* buffer to save trial row when filtering */
   png_bytep tst_row;    /* buffer to save best trial row when filtering */
#endif
   size_t info_rowbytes;      /* Added in 1.5.4: cache of updated row bytes */

   png_uint_32 idat_size;     /* current IDAT size for read */
   png_uint_32 crc;           /* current chunk CRC value */
   png_colorp palette;        /* palette from the input file */
   png_uint_16 num_palette;   /* number of color entries in palette */

/* Added at libpng-1.5.10 */
#ifdef PNG_CHECK_FOR_INVALID_INDEX_SUPPORTED
   int num_palette_max;       /* maximum palette index found in IDAT */
#endif

   png_uint_16 num_trans;     /* number of transparency values */
   png_byte compression;      /* file compression type (always 0) */
   png_byte filter;           /* file filter type (always 0) */
   png_byte interlaced;       /* PNG_INTERLACE_NONE, PNG_INTERLACE_ADAM7 */
   png_byte pass;             /* current interlace pass (0 - 6) */
   png_byte do_filter;        /* row filter flags (see PNG_FILTER_ in png.h ) */
   png_byte color_type;       /* color type of file */
   png_byte bit_depth;        /* bit depth of file */
   png_byte usr_bit_depth;    /* bit depth of users row: write only */
   png_byte pixel_depth;      /* number of bits per pixel */
   png_byte channels;         /* number of channels in file */
#ifdef PNG_WRITE_SUPPORTED
   png_byte usr_channels;     /* channels at start of write: write only */
#endif
   png_byte sig_bytes;        /* magic bytes read/written from start of file */
   png_byte maximum_pixel_depth;
                              /* pixel depth used for the row buffers */
   png_byte transformed_pixel_depth;
                              /* pixel depth after read/write transforms */
#if ZLIB_VERNUM >= 0x1240
   png_byte zstream_start;    /* at start of an input zlib stream */
#endif /* Zlib >= 1.2.4 */
#if defined(PNG_READ_FILLER_SUPPORTED) || defined(PNG_WRITE_FILLER_SUPPORTED)
   png_uint_16 filler;           /* filler bytes for pixel expansion */
#endif

#if defined(PNG_bKGD_SUPPORTED) || defined(PNG_READ_BACKGROUND_SUPPORTED) ||\
   defined(PNG_READ_ALPHA_MODE_SUPPORTED)
   png_byte background_gamma_type;
   png_fixed_point background_gamma;
   png_color_16 background;   /* background color in screen gamma space */
#ifdef PNG_READ_GAMMA_SUPPORTED
   png_color_16 background_1; /* background normalized to gamma 1.0 */
#endif
#endif /* bKGD */

#ifdef PNG_WRITE_FLUSH_SUPPORTED
   png_flush_ptr output_flush_fn; /* Function for flushing output */
   png_uint_32 flush_dist;    /* how many rows apart to flush, 0 - no flush */
   png_uint_32 flush_rows;    /* number of rows written since last flush */
#endif

#ifdef PNG_READ_GAMMA_SUPPORTED
   int gamma_shift;      /* number of "insignificant" bits in 16-bit gamma */
   png_fixed_point screen_gamma; /* screen gamma value (display_exponent) */

   png_bytep gamma_table;     /* gamma table for 8-bit depth files */
   png_uint_16pp gamma_16_table; /* gamma table for 16-bit depth files */
#if defined(PNG_READ_BACKGROUND_SUPPORTED) || \
   defined(PNG_READ_ALPHA_MODE_SUPPORTED) || \
   defined(PNG_READ_RGB_TO_GRAY_SUPPORTED)
   png_bytep gamma_from_1;    /* converts from 1.0 to screen */
   png_bytep gamma_to_1;      /* converts from file to 1.0 */
   png_uint_16pp gamma_16_from_1; /* converts from 1.0 to screen */
   png_uint_16pp gamma_16_to_1; /* converts from file to 1.0 */
#endif /* READ_BACKGROUND || READ_ALPHA_MODE || RGB_TO_GRAY */
#endif

#if defined(PNG_READ_GAMMA_SUPPORTED) || defined(PNG_sBIT_SUPPORTED)
   png_color_8 sig_bit;       /* significant bits in each available channel */
#endif

#if defined(PNG_READ_SHIFT_SUPPORTED) || defined(PNG_WRITE_SHIFT_SUPPORTED)
   png_color_8 shift;         /* shift for significant bit transformation */
#endif

#if defined(PNG_tRNS_SUPPORTED) || defined(PNG_READ_BACKGROUND_SUPPORTED) \
 || defined(PNG_READ_EXPAND_SUPPORTED) || defined(PNG_READ_BACKGROUND_SUPPORTED)
   png_bytep trans_alpha;           /* alpha values for paletted files */
   png_color_16 trans_color;  /* transparent color for non-paletted files */
#endif

   png_read_status_ptr read_row_fn;   /* called after each row is decoded */
   png_write_status_ptr write_row_fn; /* called after each row is encoded */
#ifdef PNG_PROGRESSIVE_READ_SUPPORTED
   png_progressive_info_ptr info_fn; /* called after header data fully read */
   png_progressive_row_ptr row_fn;   /* called after a prog. row is decoded */
   png_progressive_end_ptr end_fn;   /* called after image is complete */
   png_bytep save_buffer_ptr;        /* current location in save_buffer */
   png_bytep save_buffer;            /* buffer for previously read data */
   png_bytep current_buffer_ptr;     /* current location in current_buffer */
   png_bytep current_buffer;         /* buffer for recently used data */
   png_uint_32 push_length;          /* size of current input chunk */
   png_uint_32 skip_length;          /* bytes to skip in input data */
   size_t save_buffer_size;          /* amount of data now in save_buffer */
   size_t save_buffer_max;           /* total size of save_buffer */
   size_t buffer_size;               /* total amount of available input data */
   size_t current_buffer_size;       /* amount of data now in current_buffer */
   int process_mode;                 /* what push library is currently doing */
   int cur_palette;                  /* current push library palette index */

#endif /* PROGRESSIVE_READ */

#if defined(__TURBOC__) && !defined(_Windows) && !defined(__FLAT__)
/* For the Borland special 64K segment handler */
   png_bytepp offset_table_ptr;
   png_bytep offset_table;
   png_uint_16 offset_table_number;
   png_uint_16 offset_table_count;
   png_uint_16 offset_table_count_free;
#endif

#ifdef PNG_READ_QUANTIZE_SUPPORTED
   png_bytep palette_lookup; /* lookup table for quantizing */
   png_bytep quantize_index; /* index translation for palette files */
#endif

/* Options */
#ifdef PNG_SET_OPTION_SUPPORTED
   png_uint_32 options;           /* On/off state (up to 16 options) */
#endif

#if PNG_LIBPNG_VER < 10700
/* To do: remove this from libpng-1.7 */
#ifdef PNG_TIME_RFC1123_SUPPORTED
   char time_buffer[29]; /* String to hold RFC 1123 time text */
#endif
#endif

/* New members added in libpng-1.0.6 */

   png_uint_32 free_me;    /* flags items libpng is responsible for freeing */

#ifdef PNG_USER_CHUNKS_SUPPORTED
   png_voidp user_chunk_ptr;
#ifdef PNG_READ_USER_CHUNKS_SUPPORTED
   png_user_chunk_ptr read_user_chunk_fn; /* user read chunk handler */
#endif
#endif

#ifdef PNG_SET_UNKNOWN_CHUNKS_SUPPORTED
   int          unknown_default; /* As PNG_HANDLE_* */
   unsigned int num_chunk_list;  /* Number of entries in the list */
   png_bytep    chunk_list;      /* List of png_byte[5]; the textual chunk name
                                  * followed by a PNG_HANDLE_* byte */
#endif

/* New members added in libpng-1.0.3 */
#ifdef PNG_READ_RGB_TO_GRAY_SUPPORTED
   png_byte rgb_to_gray_status;
   /* Added in libpng 1.5.5 to record setting of coefficients: */
   png_byte rgb_to_gray_coefficients_set;
   /* These were changed from png_byte in libpng-1.0.6 */
   png_uint_16 rgb_to_gray_red_coeff;
   png_uint_16 rgb_to_gray_green_coeff;
   /* deleted in 1.5.5: rgb_to_gray_blue_coeff; */
#endif

/* New member added in libpng-1.6.36 */
#if defined(PNG_READ_EXPAND_SUPPORTED) && \
    defined(PNG_ARM_NEON_IMPLEMENTATION)
   png_bytep riffled_palette; /* buffer for accelerated palette expansion */
#endif

/* New member added in libpng-1.0.4 (renamed in 1.0.9) */
#if defined(PNG_MNG_FEATURES_SUPPORTED)
/* Changed from png_byte to png_uint_32 at version 1.2.0 */
   png_uint_32 mng_features_permitted;
#endif

/* New member added in libpng-1.0.9, ifdef'ed out in 1.0.12, enabled in 1.2.0 */
#ifdef PNG_MNG_FEATURES_SUPPORTED
   png_byte filter_type;
#endif

/* New members added in libpng-1.2.0 */

/* New members added in libpng-1.0.2 but first enabled by default in 1.2.0 */
#ifdef PNG_USER_MEM_SUPPORTED
   png_voidp mem_ptr;             /* user supplied struct for mem functions */
   png_malloc_ptr malloc_fn;      /* function for allocating memory */
   png_free_ptr free_fn;          /* function for freeing memory */
#endif

/* New member added in libpng-1.0.13 and 1.2.0 */
   png_bytep big_row_buf;         /* buffer to save current (unfiltered) row */

#ifdef PNG_READ_QUANTIZE_SUPPORTED
/* The following three members were added at version 1.0.14 and 1.2.4 */
   png_bytep quantize_sort;          /* working sort array */
   png_bytep index_to_palette;       /* where the original index currently is
                                        in the palette */
   png_bytep palette_to_index;       /* which original index points to this
                                         palette color */
#endif

/* New members added in libpng-1.0.16 and 1.2.6 */
   png_byte compression_type;

#ifdef PNG_USER_LIMITS_SUPPORTED
   png_uint_32 user_width_max;
   png_uint_32 user_height_max;

   /* Added in libpng-1.4.0: Total number of sPLT, text, and unknown
    * chunks that can be stored (0 means unlimited).
    */
   png_uint_32 user_chunk_cache_max;

   /* Total memory that a zTXt, sPLT, iTXt, iCCP, or unknown chunk
    * can occupy when decompressed.  0 means unlimited.
    */
   png_alloc_size_t user_chunk_malloc_max;
#endif

/* New member added in libpng-1.0.25 and 1.2.17 */
#ifdef PNG_READ_UNKNOWN_CHUNKS_SUPPORTED
   /* Temporary storage for unknown chunk that the library doesn't recognize,
    * used while reading the chunk.
    */
   png_unknown_chunk unknown_chunk;
#endif

/* New member added in libpng-1.2.26 */
   size_t old_big_row_buf_size;

#ifdef PNG_READ_SUPPORTED
/* New member added in libpng-1.2.30 */
  png_bytep        read_buffer;      /* buffer for reading chunk data */
  png_alloc_size_t read_buffer_size; /* current size of the buffer */
#endif
#ifdef PNG_SEQUENTIAL_READ_SUPPORTED
  uInt             IDAT_read_size;   /* limit on read buffer size for IDAT */
#endif

#ifdef PNG_IO_STATE_SUPPORTED
/* New member added in libpng-1.4.0 */
   png_uint_32 io_state;
#endif

/* New member added in libpng-1.5.6 */
   png_bytep big_prev_row;

/* New member added in libpng-1.5.7 */
   void (*read_filter[PNG_FILTER_VALUE_LAST-1])(png_row_infop row_info,
      png_bytep row, png_const_bytep prev_row);

#ifdef PNG_READ_SUPPORTED
#if defined(PNG_COLORSPACE_SUPPORTED) || defined(PNG_GAMMA_SUPPORTED)
   png_colorspace   colorspace;
#endif
#endif
};

/* Basic control structions.  Read libpng-manual.txt or libpng.3 for more info.
 *
 * png_struct is the cache of information used while reading or writing a single
 * PNG file.  One of these is always required, although the simplified API
 * (below) hides the creation and destruction of it.
 */
typedef struct png_struct_def png_struct;

#    ifndef PNG_RESTRICT
#      define PNG_RESTRICT __restrict
#    endif

/* Types with names ending 'p' are pointer types.  The corresponding types with
 * names ending 'rp' are identical pointer types except that the pointer is
 * marked 'restrict', which means that it is the only pointer to the object
 * passed to the function.  Applications should not use the 'restrict' types;
 * it is always valid to pass 'p' to a pointer with a function argument of the
 * corresponding 'rp' type.  Different compilers have different rules with
 * regard to type matching in the presence of 'restrict'.  For backward
 * compatibility libpng callbacks never have 'restrict' in their parameters and,
 * consequentially, writing portable application code is extremely difficult if
 * an attempt is made to use 'restrict'.
 */
typedef png_struct * PNG_RESTRICT png_structrp;


/* Read the entire image.  If the image has an alpha channel or a tRNS
 * chunk, and you have called png_handle_alpha()[*], you will need to
 * initialize the image to the current image that PNG will be overlaying.
 * We set the num_rows again here, in case it was incorrectly set in
 * png_read_start_row() by a call to png_read_update_info() or
 * png_start_read_image() if png_set_interlace_handling() wasn't called
 * prior to either of these functions like it should have been.  You can
 * only call this function once.  If you desire to have an image for
 * each pass of a interlaced image, use png_read_rows() instead.
 *
 * [*] png_handle_alpha() does not exist yet, as of this version of libpng
 */
void PNGAPI
png_read_image(png_structrp png_ptr, png_bytepp image)
{
   png_uint_32 i, image_height;
   int pass, j;
   png_bytepp rp;

   png_debug(1, "in png_read_image");

   if (png_ptr == NULL)
      return;

#ifdef PNG_READ_INTERLACING_SUPPORTED
   if ((png_ptr->flags & PNG_FLAG_ROW_INIT) == 0)
   {
      pass = png_set_interlace_handling(png_ptr);
      /* And make sure transforms are initialized. */
      png_start_read_image(png_ptr);
   }
   else
   {
      if (png_ptr->interlaced != 0 &&
          (png_ptr->transformations & PNG_INTERLACE) == 0)
      {
         /* Caller called png_start_read_image or png_read_update_info without
          * first turning on the PNG_INTERLACE transform.  We can fix this here,
          * but the caller should do it!
          */
         png_warning(png_ptr, "Interlace handling should be turned on when "
             "using png_read_image");
         /* Make sure this is set correctly */
         png_ptr->num_rows = png_ptr->height;
      }

      /* Obtain the pass number, which also turns on the PNG_INTERLACE flag in
       * the above error case.
       */
      pass = png_set_interlace_handling(png_ptr);
   }
#else
   if (png_ptr->interlaced)
      png_error(png_ptr,
          "Cannot read interlaced image -- interlace handler disabled");

   pass = 1;
#endif

   image_height=png_ptr->height;

   for (j = 0; j < pass; j++)
   {
      rp = image;
      for (i = 0; i < image_height; i++)
      {
         png_read_row(png_ptr, *rp, NULL);
         rp++;
      }
   }
}
```

### Code Review

1. `populate_map_and_metrics` is true, therefore the following check is passed:

```c
if ( error                                    ||
         ( !populate_map_and_metrics              &&
           ( (FT_Int)imgWidth  != metrics->width  ||
             (FT_Int)imgHeight != metrics->height ) ) )
      goto DestroyExit;
```

It means that `imgWidth` and `imgHeight` are ACID, as `png` is fully user-controlled (due to `stream`). 
It also means that `map` and `metrics` are also ACID.

2. `metrics` defines its `width` and `height` attributes as `ushort`, meaning 2 byte values. 

On the other hand, `map` defines its `width` and `rows` attributes as `unsigned int` (usually 4 bytes), while `imgWidth` and `imgHeight` are defined as `uint32_t`. 

It means there is a possible integer truncation for setting the `metrics` attributes, as can be seen by the casting. \
Because `map` sets its attributes based on `metrics` attributes, it will assign truncated integer values!

Note there is no overflow for `map->pitch`, as it is 4-bytes long, and a maximal assigned value of `0xffff * 4`.

3. Possible integer overflow and use-after-free:

```c
FT_NEW_ARRAY( rows, imgHeight ) //KC: realloc(rows, imgHeight*sizeof(ptr)), and memset()
```

Because `imgHeight` is controlled, and there is no lower-bound sanity check, it is possible to set its value to `0`. \
That way, `realloc` actually being used as `free`, making `rows` point towards freed memory. 

Another major problem, is the possible integer overflow. 
While the sanity check verifies the lower 2-bytes of `imgHeight` doesn't pass the value of `0x7fff`, its upper 2-bytes are completely user-controlled.
It means the maximal value of `imgHeight` is `0xffff7fff`. \
By multiplying this value with `sizeof(ptr) = 4`, there is a clear integer overflow, hence yields an under-allocation for the `rows` array. 

It translates to heap buffer overflow:

```c
for ( i = 0; i < (FT_Int)imgHeight; i++ )
  rows[i] = map->buffer + ( y_offset + i ) * map->pitch + x_offset * 4;
```

As the `map` content is also controlled. 

### Patch

The size checks were performed on `imgHeight` and `imgWidth` instead. 


## CVE-2020-17087 - Windows Kernel CNG ioctl

### Code

```c
////ACID:SourceBuffer, SourceLength
NTSTATUS CfgAdtpFormatPropertyBlock(PBYTE SourceBuffer, 
                                    USHORT SourceLength, 
                                    PUNICODE_STRING Destination)
{
	CONST USHORT DestinationSize = (USHORT)(6 * SourceLength);
	PWCHAR OutputBuffer = BCryptAlloc(DestinationSize);

	for (USHORT i = 0; i < SourceLength; i++) {
		*OutputBuffer++ = "0123456789abcdef"[*SourceBuffer >> 4];
		*OutputBuffer++ = "0123456789abcdef"[*SourceBuffer & 0xF];
		*OutputBuffer++ = ' ';
		SourceBuffer++;
	}

 	Destination->MaximumLength = DestinationSize;
 	Destination->Length = DestinationSize - 2;
 	Destination->Buffer = OutputBuffer;

	return STATUS_SUCCESS;
}
```

### Code Review

1. There is an integer overflow, along with integer truncation at the first line. 

In case the value of `SourceLength` exceeds `65536 / 6`, the integer overflow along with the truncation, would yield lower value for `DestinationSize`.
For example, `SourceLength = 0x3000` would yield `6 * SourceLength = 0x12000`, and `DestinationSize = 0x2000 < SourceLength`. 

2. This size truncation leads to a heap under-allocation for `OutputBuffer`. 

3. Another bonus bug is, is the last possible integer-underflow being performed on an unsigned variable:

```c
Destination->Length = DestinationSize - 2;
```

Which can be used to create extremely large (65536 bytes) values of `->Length`, while setting low value of `DestinationSize`. 

### Patch

No released patch.


## CVE-2021-33909 - Sequoia (Linux kernel VFS seq_file)

seq_file is a kernel interfance, that produces *virtual files* to userspace.

They maintain typical open, read, seek semantics - but allows communication between userspace and kernelspace. \
Each file contains sequences of records, which the kernel support iterating on. 

Note those are not "real" files, that are stored on disk storage. 

Example for such files are under the `procfs` virtual dir. 

### Code 

```c
////NOTE: Start reading the code at seq_read_iter()

/**
 * seq_has_overflowed - check if the buffer has overflowed
 * @m: the seq_file handle
 *
 * seq_files have a buffer which may overflow. When this happens a larger
 * buffer is reallocated and all the data will be printed again.
 * The overflow state is true when m->count == m->size.
 *
 * Returns true if the buffer received more than it can hold.
 */
static inline bool seq_has_overflowed(struct seq_file *m)
{
	return m->count == m->size;
}

//------------------------------------------------------------------------
135 static int show_mountinfo(struct seq_file *m, struct vfsmount *mnt) //KC: called by "m->op->show(m, p)" 
136 {
...
150                 seq_dentry(m, mnt->mnt_root, " \t\n\\");
//------------------------------------------------------------------------
523 int seq_dentry(struct seq_file *m, struct dentry *dentry, const char *esc)
524 {
525         char *buf;
526         size_t size = seq_get_buf(m, &buf);
...
529         if (size) {
530                 char *p = dentry_path(dentry, buf, size);
//------------------------------------------------------------------------
380 char *dentry_path(struct dentry *dentry, char *buf, int buflen)
381 {
382         char *p = NULL;
...
385         if (d_unlinked(dentry)) { //KC: assume true
386                 p = buf + buflen;
387                 if (prepend(&p, &buflen, "//deleted", 10) != 0)
//------------------------------------------------------------------------
 11 static int prepend(char **buffer, int *buflen, const char *str, int namelen)
 12 {
 13         *buflen -= namelen;
 14         if (*buflen < 0)
 15                 return -ENAMETOOLONG;
 16         *buffer -= namelen;
 17         memcpy(*buffer, str, namelen);
//------------------------------------------------------------------------

////ACID: Assume the attacker can control the underlying seq_file to cause the while(1) loop to occur as many times as they want
168 ssize_t seq_read_iter(struct kiocb *iocb, struct iov_iter *iter)
169 {
170         struct seq_file *m = iocb->ki_filp->private_data;
...
205         /* grab buffer if we didn't have one */
206         if (!m->buf) { //KC: assume this is NULL on the first iteration
207                 m->buf = seq_buf_alloc(m->size = PAGE_SIZE); //KC: m->size is a size_t
...
210         }
...
220         // get a non-empty record in the buffer
...
223         while (1) {
...
227                 err = m->op->show(m, p); //KC: This calls to show_mountinfo()
...
236                 if (!seq_has_overflowed(m)) // got it
237                         goto Fill;
238                 // need a bigger buffer
...
240                 kvfree(m->buf);
...
242                 m->buf = seq_buf_alloc(m->size <<= 1);
...
246         }
```

### Code Review

1. attacker may control the amount of while loop iterations. 
Because of the following line:

```c
m->buf = seq_buf_alloc(m->size <<= 1);
```

There is an integer overflow.
`PAGE_SIZE` is usually `0x1000`, and after `2**32 / 0x1000` iterations, the allocation size would wrap-around to 0 bytes. 

This would result with an under-allocation for `m->buf`. 

2. `show_mountinfo()` calls `seq_dentry`, which extracts data from our user-controlled `m` towards `buf`, as well as the `size_t size` variable. 
Note this variable is defined as an unsigned integer!

3. `dentry_path` implicitly converts `buflen` into signed integer. \
This means that a large value of `size`, for example `0xffff`, would be translated to `-1`, potentially allowing OOB write to the `p` array, which would now point towards memory before the allocated `buf`. 

4. `prepend` has a basic sanity check for the `buflen` value:

```c
*buflen -= namelen;
 14         if (*buflen < 0)
 15                 return -ENAMETOOLONG;
```

It means that for an extremely low `buflen` signed value, for example `0x80000000`, a substraction of `namelen` (10) would actually flip it towards a positive value - `0x7ffffff6` . This value can pass the sanity check performed on `buflen`. 


This will result with an OOB-W for the `p` (or `buffer`) allocated address:

```c
memcpy(*buffer, str, namelen);
```

### Patch

Added `size` validation for `seq_buf_alloc`. 

## Extra CVEs For Learning

```bash
CVE-2021-22414
CVE-2021-33742
CVE-2020-10027
CVE-2020-10021
```
