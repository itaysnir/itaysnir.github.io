---
layout: post
title:  "GCC Sanitizers"
date:   2023-03-24 19:59:44 +0300
categories: jekyll update
---

**Contents**
* TOC
{:toc}
## General

Sanitizers are great. \
Those are extra run-time checks injected into the compiled binary, that may alert about bugs and vulnerabilities. 

This is useful both for vulnerability research and fuzzing, as well as development (running tests on sanitized version may warn about many hard-to-find bugs).

## ASAN

The first popular sanitizer is ASAN. \
It can be enabled by using the `gcc` flag: `-fsanitize=address`. 

In order to make aggressive diagnostics, we should add:

```bash
CFLAGS += -fsanitize-address-use-after-scope
ASAN_OPTIONS=strict_string_checks=1:detect_stack_use_after_return=1:check_initialization_order=1:strict_init_order=1
```

In order to see the full list of supported `ASAN_OPTIONS`, issue `ASAN_OPTIONS=help=1 ./a.out`. \
Extra recommended configuration: 

```bash
verbosity=2
quarantine_size_mb=<SOME_HIGH_VALUE>
debug=1
```

Note that in case of an `.so` compiled with ASAN, but needs to run on an unsanitized executable, we can use `AddressSanitizerAsDso`, which is ASAN as a shared library. \
See [link][asan-so] for more details. 

For generic information about ASAN, see [here][asan] and [here][asan-blog] for details.

## PSAN

Pointer sanitizer, enabled via `-fsanitize=pointer-compare` and `-fsanitize=pointer-subtract`. \
Can be used with ASAN, but not with TSAN. 

Moreover, add the following key to `ASAN_OPTIONS`:
`detect_invalid_pointer_pairs=2`. 

## TSAN

ThreadSanitizer, fast data race detector for C and C++. \
Enabled via `-fsanitize=thread`. 

Note it cannot be used with ASAN and LSAN. 

For aggressive diagnostics, the following `TSAN_OPTIONS` configuration addition is recommended:

```bash
history_size=7
```

## LSAN

LeakSanitizer, memory leak detector. \
It is already integrated into ASAN, but may be useful whenever the executable is linked towards `.so` that overrides `malloc`, and defines its own allocator. 
 
## MSAN

Detects uninitialized memory reads. \
Currently, it is only supported by clang, not GCC. \
It may be enabled via `-fsanitize=memory`. 

## UBSAN

Undefined behavior detector. 

Further reading: [link][ubsan]. 

## Extra GCC Flags

Extra checks that may find stack / vtable corruptions: 

```bash
-fstack-protector-all
-fstack-check
-fstack-clash-protection
-fvtable-verify=std
```


[asan]: https://github.com/google/sanitizers/wiki/AddressSanitizer
[asan-blog]: http://gavinchou.github.io/experience/summary/syntax/gcc-address-sanitizer/
[asan-so]: https://github.com/google/sanitizers/wiki/AddressSanitizerAsDso
[ubsan]: https://clang.llvm.org/docs/UndefinedBehaviorSanitizer.html
