---
---
layout: post
title:  "Javascript Recap"
date:   2024-01-29 19:59:44 +0300
categories: jekyll update
---

**Contents**
* TOC
{:toc}
## Introduction

JS can execute not only in browsers (clients), but also on servers or any device that has JS engine (such as V8, that also runs within Node.js). 

Chrome, Opera and Edge all uses the `V8` JS engine, while Firefox uses `SpiderMonkey`. 

The JS engine parses the js script, compiles it to machine code, performing multiple optimizations, and runs it. 

In-browser js is able to add new HTML to a page, change existing content, react to user actions, send requests the remote servers, get and set cookies, remember local storage, etc. 

However, in order to protect users against malicious webpages, in-browser js cannot R/W arbitrary files on the disk, execute programs, direct access to OS functions. \
Moreover, different tabs are usually "isolated", and js from one page cannot access the other page if they come from different sites ("same origin policy"). 

Notice there are other languages created over JS (transpiled to js before they run in the browser), such as `TypeScript` (adds strict data typing). 

## Manuals, Specifications

