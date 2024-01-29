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

### General

JS can execute not only in browsers (clients), but also on servers or any device that has JS engine (such as V8, that also runs within Node.js). 

Chrome, Opera and Edge all uses the `V8` JS engine, while Firefox uses `SpiderMonkey`. 

The JS engine parses the js script, compiles it to machine code, performing multiple optimizations, and runs it. 

In-browser js is able to add new HTML to a page, change existing content, react to user actions, send requests the remote servers, get and set cookies, remember local storage, etc. 

However, in order to protect users against malicious webpages, in-browser js cannot R/W arbitrary files on the disk, execute programs, direct access to OS functions. \
Moreover, different tabs are usually "isolated", and js from one page cannot access the other page if they come from different sites ("same origin policy"). 

Notice there are other languages created over JS (transpiled to js before they run in the browser), such as `TypeScript` (adds strict data typing). 

### Manuals, Specifications

[ECMA-262][ECMA-262] contains the most formalized information about js, and defines the language. \
But for everyday use, `devdocs.io` is usually enough.

A great manual is Mozilla's MDN JS Reference: [MDN][MDN].

### Developer Console

Within developer tools - all browsers has them, but usually Chrome and Firefox's are the best. \
Open with `F12`. \
Mandatory for debugging!

## JS Fundamentals

### Hello, world

JS programs can be inserted into HTML documents via `<script>`. \
The code within the tag is automatically executed when the browser processes the tag. 

```html
<!DOCTYPE HTML>
<html>

<body>

  <p>Before the script...</p>

  <script>
    alert( 'Hello, world!' );
  </script>

  <p>...After the script.</p>

</body>

</html>
```

The `<script>` tag have few attributes that are common with old code:

`type` - old HTML standard required a script to have a type. \
Usually it was `type="text/javascript"`. 

`language` - no longer makes sense, as JS is the default language. 

Notice we can export JS code to seperate file. \
In that case, we can attach script via the `src` attribute:

```html
<script src="/path/to/script.js"></script>
```

We can also specify relative path. \ 

The benefit of separate file, is that the browser will download it, and store it in its cache. 

### Code Structure

It is a good practice to use semicolon between statements. 

Comments are line in `C`: `//` for line comment, `/* */` for block. \
Comments are friends. Use them.

### "use strict";

When it is located at the top of the script, the whole script is interpreted the "modern" way, not the old-compatible way.

Notice it *must* be at the top of the scripts, otherwise `"use strict";` is ignored.

As long as we use classes and modules, `use strict` is enabled automatically. 

### Variables





[ECMA-262]: https://ecma-international.org/publications-and-standards/standards/ecma-262/
[MDN]: https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference
