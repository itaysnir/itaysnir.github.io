---
layout: post
title:  "One Days - Use After Free"
date:   2022-11-21 20:00:01 +0300
categories: jekyll update
---

**Contents**
* TOC
{:toc}
## IDE Note

At this point I've started to use [Ecplise C / C++ package][eclipse] for code auditing. 

This IDE works pretty good under large scale of platforms (Linux, Windows, Different Archs and compilers, etc), similar to VScode (and unlike Clion). \
However, unlike VScode, it has even better static parsing mechanism, and faster navigation times. 

### Eclipse Configuration

By initializing Eclipse, select *Create C or C++ project* -> *Makefile Project*, and uncheck the *Generate Source and Makefile* option. 

Then, go to *Window* -> *Preferences* -> *Scalability*, and uncheck *Disable editor live parsing*, as well as *Alert me when scalability mode turned on* (which stops doing parsing for large files). \
Finally, change the scalability lines threshold to `999999` instead of `5000`.  

Next, type *Folding*, and select both *Enable folding of preprocessor branchs*, as well as *Enable folding of control flow statements*. 

Afterwards, drag the project source folder into the workspace bar within the IDE (use *Link to Files and Folders* for projects involving many checkouts). 

After the indexing procedure has completed, right click on the project's properties. \
Navigate to *C / C++ Include Path* -> *Add Preprocessor Symbol*, and set interesting symbol values (may display different code paths, depending on `#ifdefs` for example). 

### Navigation




## Background


## CVE-BLA

### Code

### Code Review

### Patch

[eclipse]: https://www.eclipse.org/downloads/packages/release/2022-12/r/eclipse-ide-cc-developers