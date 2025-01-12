---
layout: post
title:  "Pork CTF!"
date:   2025-01-12 20:59:45 +0300
categories: jekyll update
---

**Contents**
* TOC
{:toc}
## Pork CTF!

Recently, a friend of my have developed interesting vuln research CTF. It focuses on finding a "very hard vulnerability", that should be easy to pwn. \
The challenge is taken from: [url][pork-url]

## Overview

The app is a simple notes server, that allows `create, read, delete` notes. \
The server runs on a regular Android application, and the notes are stored in the app FS. \
The goal is to get the flag from the "ADMIN" user notes. 

The app's sources aren't that large - total of 4 files, `pork.cpp, notes.cpp` and their `.h` variants. 

## Vuln Research

### Java_com_pork_MainActivity_initialize

The main entry point. 

1. Starts by calling `fork` (leaving the UI thread), and then `mkdir` of the user's directory. It then creates the `ADMIN` user, using `create_user`, and changes the current user via `set_current_user`.

2. Sus - while `create_user` receives raw `const char*`, which is a constant pointer, `set_current_user` receives `const std::string&`. This means the literal string is constructed as `std::string`, passes the reference to the function `set_current_user`, and by the end of it - destructs the `std::string`, as its storage duration is only valid for the parameter's lifetime. But if the `username` `std::string` reference / internal string pointer won't be saved anywhere, this is OK. 

3. It then checks the notes count, and if it is `0`, create a single note via `create_note`. This single note contains the CTF flag. 

4. It erases the password literal string off the stack, by doing some cryptic code - retrieving the stack's address via `pthread` utilities, and memsets to `0` address that SHOULD contain the admin's password. 

5. Initializes the server's socket, which can listen for up to `10` connections at once. There might be interesting vuln involving multiple client connections. Eventaully, a new thread is spawned for each new connection (all sharing the same memory space), calling `handle_client`. 

### handle_client

Runs within a loop, having menu of options. 

1. Reads a single byte option into a buffer. The `recv` retval check only verifies if the return value is `-1`. A better check would be `== sizeof(buffer)`. Yet, not a vuln.

2. Dispatches the handlers: `login, logout, change_pw, create_note, delete_note, get_note, move_to_thread, disconnect`. Of course, the most SUS handler is `move_to_thread`, as why the hell would we like such an option?

3. The default (invalid option) is sending back an invalid message prompt.

### close_socket_and_send

If there's a message, sends it via `socket_send`, closes the socket and the running thread. 

1. Sus - are there any other resources that needs to be released before terminating the thread?

2. `close` retval isn't checked. 

### socket_send

Sends a message by first sending a packet containing a single byte, denoting its length, and then the message itself. 

1. Sus - there are no `send` retval checks at all. I'd expect an assertion for the correct size of bytes sent successfully.

### login

1. After receiving a user and verifying its path, performs another check of the received size. Notice the username buffer can be up to `0x19` bytes including the null terminator. 

2. Sus - receives arbitrarly long `password`, also storing it as a unique pointer. Notice this buffer's content is completely arbitrary (but null terminated).

3. Calls `set_current_user`, by sending the raw pointers of the unique pointers, which is sus. 

4. calls `user_exists`. If it is, compares the password to the storage. If its not, calls `create_user`. 

5. **Extremely sus, maybe vuln** - TOCTOU, as there's first a check that `user_exists`, using the file system, and only then `create_user` is called. This means that if we would spawn two threads having the same username, they may both enter the code flow of `create_user` simultaneously. 

### recv_sized

Receives a single byte off the socket, denoting the size to-be-received. 

1. Correctly checks `recv` retval, and verifies `size != 0, size < 0xff`.

2. Allocates buffer of size `size + 1`, and truncates it properly. Then reads `size` bytes to fill that buffer. Hence, it properly reasd the buffer, which may contain completely arbitrary content. 

3. Calls `fail_if_admin`, verifying the `"ADMIN"` string isn't located within the buffer at all. This pattern is abit wierd, as I wouldn't expect a simple receive function to also perform such content check.

4. Notice the sent buffer is `std::unique_ptr`, having reference count of 1. The call of `fail_if_admin` is done by sending the raw pointer of the buffer, `buffer.get()`, which is a bad practice - as now this pointer (which may get invalidated) also resides somewhere else. In this case, within the `std::string` construction. 

### fail_if_admin

1. Implicitly converts `char[]` to `const std::string&`, hence - generates `std::string` for this method's lifetime. Sus, but not a bug. 

2. Searches the admin's username via `find`, which seems to be correct. 

### check_path

Performs extra sanity checks regarding the username - only alphanumeric characters, and username length of up to `0x18` bytes. 

1. Notice - the check verifies that the username's real name is `0x18` bytes. This means that including the null terminator, the name may be up to `0x19` bytes. 

### set_current_user

1. Sus - implicitly constructs `std::string` references out of the parameters. However, these references aren't stored anywhere else.

2. Retrieves the stack using the cryptic `get_stack_safe` function

3. **Extremely sus, probably vuln** - performs unbounded copy of the password string towards the stack. Recall the password's size isn't properly bounded (may be up to `0xfe`), and `0xff` bytes including the null terminator. This whole buffer is `memcpy`'d into `stack` address. 

4. Notice, it uses the `std::string::length` to determine the amount of bytes to copy. What if there's null byte in the middle of the string? Recall these `username, password` parameters are **implicitlly generated** as `std::string`. If it would count bytes past the null terminator, we would also copy bytes past the null terminator!

5. Using the above finding, notice that instead of using `password.length()`, upon performing the copy of the username string, its targed address is determined by `strlen(stack)` - which is truncated on the first occurance of a null byte. Hence, We might create overlapping writes, where the username string would overwrite some of the password's bytes! This is very interesting, as it would allow us to create a buffer that would contain the `"ADMIN"` string within its name. 

6. After some experimenting, if constructing `std::string` off an embedded-null string pointer, such as `"AA\0AAA"`, the string would be constructed as `AA`, having length of 2. Hence, this won't be trivially exploitable. However, `std::string`s CAN contain embedded null bytes, for example by using `push_back` or concatenating to other strings with `operator+`, or `operator[]`. 

The main purpose of this method, as I see it, is to create a possible scenario where both username and password strings together forges an `"ADMIN"` string. This can be made if only the password `std::string` would contain an embedded null byte. 

### get_stack_safe

Retrieves the thread's local stack base, and adds certain offset to it. 

1. Sus: while the offset contains 2 pages (to pass page guard?), it also contains some un-aligned offset- `0x69`. This means that writes to the resulting `stack` address won't be atomic, as the resulting address won't be aligned. This means the first 3 bytes (if 32-bit) or first 7 bytes (if 64-bit) are vulnerable to multithreaded writes. 

2. Notice the stack is per-thread stack. So its not trivial how the above finding can be exploited. 

3. Notice the stack is actually being retrieved by OOB access.. accessing bytes ABOVE the allocated stack's start would actually access the previous thread's stack. 

### create_user

As mentioned, theres a TOCTOU vuln within the `login` function, allowing simultaneous calls of this function. \
This method creates the user directory and its password file, and writes the password to this file. 

1. Extremely important - what would happen in case 2 writers would try to write different content into the password file? Recall each thread contains its own stack, and the passwords are null terminated. However, for extremely long passwords, would we be able to generate a password that won't contain null byte / would contain multiple null bytes?

### logout

Retrieves the stack, and writes empty strings as username and password. 

1. Very sus: while the first byte (start of `password`) is null'ed, the first byte of username isn't terminated in this case. Recall the sent username cannot be empty, as `check_path` verifies its length is at least `1`. 

### change_password

As before, receives unlimited bytes of arbitrary content password string, and updates the password file of the user. 

1. As before, what would happen in case multiple threads would attempt changing different passwords of the same user? Would we get corrupted password file, potentially not having any null byte?

2. In particular, recall the username buffer resides right after the password's buffer. How many bytes would `password.get()` actually write? Would it be truncated at `\x00`, or potentially continue beyond, towards the username string too? After some experimenting, it seems to be writing content, up to `\x00` byte.

### creates_note_action

Receives a note, and stores it within the filesystem. \
Many sus notes:

1. The `note` can be arbitrarly large, and contain any content. 

2. A note can be empty, in that case - it would only contain a single null byte. 

3. Also seems to be vulnerable to multithreads - what would happen incase multiple threads would write notes? 

4. If the number of notes reaches some particular value, `0x69`, **the process forks**, the parent terminates, and the flows continues only within the child process. This is particular interesting behavior, hence the vuln has something to do with multithreading. What's the implication of this? The fork'ed child should have to exact memory space as its parent, yet - it does NOT shares it with the other original running threads. 

### create_note

Sanity checks the return value of `new_note_index` isn't above `200`, to prevent integer overflows. \
Based on the note's index, creates a file with that index name, and writes the arbitrary content into that file. 

1. Sus - for multiple threads, we would be able to write multiple times into the note, potentially increasing its size past its maximal length of `0xfe`. 

### get_note_action

Fetches the desired index, and calls `get_note` on that index. 

1. Vuln - doesn't performs sanity check regarding the `recv` retval. Hence, `index` may remain uninitialized. In that case, whatever uninitialized value was there would serve as the index of the note. If we would create `255` notes, each having different content, we could leak the stack content that was on the `index` based on the retrieved answer. This would only leak a single byte that lays on the stack, not too useful. 

### get_note

Unlike `create_note`, doesn't sanity checks the return value of `get_notes_count`. This means that `index` may be some very high value. \
Returns the note as `std::string`, and not a raw pointer. 

### delete_note_action

Retrieves index in a similar manner to `get`. \
Calls `delete_note`.

### delete_note

Retrieves the note path, and deletes it. 
Notice the filename is determined by `std::to_string(index)`. 
There's a very interesting comment about this function and multithreading:

*`std::to_string` relies on the current C locale for formatting purposes, and therefore concurrent calls to std::to_string from multiple threads may result in partial serialization of calls* \

Would this mean we can corrupt the return value of `to_string`? 

*The results of overloads for integer types do not rely on the current C locale, and thus implementations generally avoid access to the current C locale in these overloads for both correctness and performance. However, such avoidance is not guaranteed by the standard.*

HMM - so by following the standard, `uint8_t` should not have that problem. However, do Android developers have followed the standard?

Whether or not this was the challenge's purpose, the fact that `to_string` may return partially-serialized content under MT environemnt is very interesting. 



### get_notes_count

Gets the notes count by traversing over the amount of entries within the user's directory.

1. Sus: clear vuln to multithreading - what would happen if one thread would read the amount of notes, and another one would add/ delete notes simultaneously?

2. Vuln - integer overflow. The notes count is stored within `uint8_t`. This value would wrap around in case we would have many notes.

3. Vuln - integer mismatch. `uint8_t` is returned, yet the actual returned variable is an `int`, which is initialized to `-1`. This means that in case there won't be any note, `-1` should be returned, being parsed as `255` legitimate entries. 


### Summary

`get_current_user` returns a pointer to username we may fake:

```c
const char *stack = get_stack_safe();
return stack + strlen(stack) + 1;
```

If after `strlen` calculation ends, and before the pointer is actually dereferenced, we'd change the content of `password` via `change_password`, we could access an offset that actually contains the `ADMIN` string. \
For example:

```bash
USERNAME=USER
PASSWORD=PASS
--> BUF = PASS\0USER\0

USERNAME=USER
PASSWORD=KKKKKADMIN
--> BUF = KKKKKADMIN\0USER\0
```

The challenge here, is the fact that each thread is having its own `stack`. \
There are few notes we haven't used, that can help us:

1. Use the `MOVE_TO_THREAD` handler, which would create a fresh new thread. In particular, is there some sort of stack-reuse mechanism? 

2. Use the filesystem races - the contents of `password, note` in particular (as those are the only targets of `rdbuf`).

3. The address of `stack` is unaligned, hence - can produce non-atomic writes. 

4. Upon creating many notes, the thread is being `fork`ed to completely different address space, preventing it from touching shared memory between multiple threads. 

Option(2) seems clear - once we've already logged in to certain user, some other thread can pick the exact same username, and change the password within a race. By doing so, we can pass the `can_login` (is password OK) check, even if we'd insert a different password than the one within the filesystem. 


[pork-url]: https://github.com/Schwartzblat/pork_ctf
