---
layout: post
title:  "One Days - OOB Writes"
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

Note: there are cases where OOB is way stronger than regular BOF.
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

0. Uninitialized local buffers `ptrs, values`.

1. Since `g_font->numMasters` is controlled, we control the loop iteration count.

Note `i` is defined as a signed integer (so there might have been integer overflow). 

However, the iteration count is still limited to `0 <= num <= 16`.

There is a clear OOB write, as `ptrs` is an array of only two pointers. 

Note there is also possible OOB read of the source `SomeArray[]`, depending on its size. However, this array is not attacker-controlled. 

By setting the iteration count to `numMasters >= 3`, attacker may override memory beyond `ptrs[]`. (Note this is compiler-dependent, as the locals order on the stack may be opposite. Usually MSVC have reverse locals order compares to gcc).

2. `values_read` is defined as int, instead of uint. 

3. The second loop allows controlling the exact content of `ptrs` array.

`values` is controlled by `GetOpenFixedArray`, and there is another OOB write as `numMasters` is attacker-controlled.

Therefore there is an OOB for the `values` array. 

3. The last loop allows OOB write of controlled data, `values`, to the return address, which is beyond `ptrs`. 

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
A `sprintf()` is being used, for a buffer of length 150 bytes. 

The longest entered string is about 50 bytes: `"Error reading header / image subheader data lengths"`.

Moreover, every `%ld` specifier may take up to 19 bytes, due to largest possible value of `9223372036854775807`. 

3. Integer overflow that can lead to heap under-allocation:

Since attacker may control `number_of_DESs`, it may tweak the `malloc` call:

```c
malloc(sizeof(segment_info_type) * number_of_DESs);
```

In case `sizeof(segment_info_type) * number_of_DESs` overflows, for example `sizeof() == 16` and `number == 0x10000000`, it will result with `malloc(0)`, hence malloc returning a zero-length buffer, allowing easy heap buffer overflow.

Note this isn't trivialally exploitable, as only the first 3 bytes of the file serves as the length, hence resulting with maximal length of `0x00ffffff`. 
In case `sizeof(segment_info_type) > 16`, this IS exploitable tho. 

Another possibilty is to insert huge `number_of_DESs` (up to `0x00ffffff`), as there is no size check at all, and perform huge buffer allocation.


4. Another integer overflow + OOB write:

```c
read_verify(hNITF, sBuffer, 13 * number_of_DESs);
```

Like previously, may set `number_of_DESs` so that overflow would occur, and it will verify 0 bytes, and the check would pass.

Moreover, `sBuffer` is a fixed-size buffer, while `number_of_DESs` is controlled. 

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

`number_of_DESs` is fully controlled, and contains some positive value.

In case of an under-allocation of the heap (due to integer overflow), `DES_info` will be overflowed by attacker-controlled input (as `Gstr` is crafted by the file's content).


6. OOB read - 

`number_of_DESs` is controlled, and `temp = sBuffer` is a fixed-size static buffer.

For large `number_of_DESs` value, `temp` would be increased over and over, yielding OOB read towards the `Gstr` buffer, hence towards `DES_info`.

### Patch

None.


## CVE-2020-27930 - Apple Fonts - libType1Scaler

