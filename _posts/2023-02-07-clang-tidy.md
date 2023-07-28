---
layout: post
title:  "Static Analyizers"
date:   2023-02-21 19:59:43 +0300
categories: jekyll update
---

**Contents**
* TOC
{:toc}
## Clang Tidy

Clang-tidy is a pretty good static analyzer tool. \
It can be used to find some non-trivial bugs in C / C++ programs.

A configuration file can be used, `.clang-tidy`, to include some sophisticated checks configurations. 

### Installation 

```bash
sudo apt install clang-tidy-15
```

### .clang-tidy Skeleton

```yaml
Checks: "-*,\
-clang-diagnostic-*,\
clang-analyzer-*,\
bugprone-*,\
misc-*,\
modernize-*,\
cert-*,\
cppcoreguidelines-*,\
hicpp-*,\
"
WarningsAsErrors: true
AnalyzeTemporaryDtors: false
FormatStyle: none
HeaderFileExtensions: ['h', 'hh', 'hpp', 'hxx']
ImplementationFileExtensions: ['c', 'cc', 'cpp', 'cxx']
HeaderFilterRegex: 'Source/cm[^/]*\.(h|hxx|cxx)$'
CheckOptions:
  - key:   modernize-use-default-member-init.UseAssignment
    value: '1'
  - key:   modernize-use-equals-default.IgnoreMacros
    value: '0'
```

### Inspecting Options

In order to display any check possible configure-able options, issue: 

```bash
clang-tidy-15 -checks=* --dump-config
```

### Cmake Integration

The correct way is to utilize dedicated tool, `run-clang-tidy.py`, in order to run clang-tidy multiple times in parallel on different translation units. 

First, make sure the build generated `compile_commands.json` file. \
Set the cmake flag `-DCMAKE_EXPORT_COMPILE_COMMANDS`, and validate the generated file is stored on the source project tree. 

Then, download a [run-clang-tidy.py][clang-tidy-script] file, and save it under the source project path. 

Finally, execute a command similar to this:

```bash
run-clang-tidy.py -header-filter='.*' -checks='-*,modernize-use-nullptr'
```

In case `-checks` is not specified, the `.clang-tidy` configuration file would be taking place. \ 
See [here][detailed-clang] for more details. 

## flawfinder

Pretty decent at pointing towards classic risky C functions.

### Installation & Usage

```bash
python3 -m pip install flawfinder

python3 -m flawfinder -c -m 0 --neverignore /path/to/sources
```

## cppcheck

[clang-tidy-script]: https://github.com/llvm-mirror/clang-tools-extra/blob/master/clang-tidy/tool/run-clang-tidy.py
[detailed-clang]: https://www.kdab.com/clang-tidy-part-1-modernize-source-code-using-c11c14/
