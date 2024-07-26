---
layout: post
title:  "JS Recap"
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

Using the `let` keyword:

```js
let message = 'Hello!';  // declare + define

alert(message);
```

Older scripts use the `var` keyword, instead of `let`. 

To declare a constant variable, use `const`. \
It is a good practice to use uppercase letters for them:

```js
const COLOR_RED = "#F00";
const COLOR_BLUE = "#00F";

let color = COLOR_BLUE;
alert(color);
```

### Data types

#### number

A value is always associated with a type. \
`number` represents both integer and floats. There are also special numbers - `Infinity, -Infinity, NaN`. Those are also of type `number`.

#### bigint

The maximal representation of an integer number is `2^53 -1`. \
In order to represent more, `bigint` was introduced, which uses the `n` specifier by the end of the number. 

```js
const bigInt = 12312412424562546234653452435n;
```

Notice that this feature is relatively new, introduced within Chrome-67. 

#### Quotes

Regarding quotes, there are 3 types - double, single and backticks. \
Double and single are simple quotes, and they're practically the same. Backticks are "extended" quotes - allows embedding variables and expressions into the string, by wrapping them with `${...}`. Similar to `fstrings` in python. 

```js
let name = "itay";

// embed a variable
alert( `Hello, ${name}!` ); // Hello, John!
```

#### boolean

Simply either `true, false`. 


#### null

Another interesting value is `null` - which have its own separate type. It does not represent invalid reference or pointer - but a placeholder representing an empty or unknown value. 

#### undefined 

The value `undefined` also stands out, also have its own type. It denotes variables that were declared but not assigned. While it is possible to assign `undefined` to a variable, the good practice is to assign it a `null`, and catch uninitialized variables by noticing their value is `undefined`. 

#### Objects and Symbols

While the primitive types values can only contain a single thing, `object` can store collections of data, and complex entities. \
The `symbol` type creates unique identifier for objects. \
More on these later.

#### typeof

Operator that returns the type of the operant. 

```js
typeof undefined // "undefined"

typeof 0 // "number"

typeof 10n // "bigint"

typeof true // "boolean"

typeof "foo" // "string"

typeof Symbol("id") // "symbol"

typeof Math // "object"  (1)

typeof null // "object"  (2)

typeof alert // "function"  (3)

typeof(0) // Less common, but same behavior. 
```

Notice:

`Math` is a builtin object, provides mathematical operations. \
The result `typeof null` returns `object` due to an error in `typeof`. This kept for compatibility. 
It seems as there's also a `function` type, but actually there is not. Functions belong to the object type, but `typeof` treats them differently. This can be convenient though. 


#### Basic Data Types

8 basic data types, all of them contains only lowercase characters. \
Out of them, 7 primitive data types: `number, bigint, string, boolean, null, undefined, symbol`, and one non-primitive - `object`.

### Interaction

Done by `alert, prompt, confirm`. 

`alert` pops a new message windown (**modal window**), contains an `OK` button. 

`prompt` requests an input using a window with `OK` and `CANCEL` options. It may contain optional default value for that input. \
Its signature: `result = prompt(title, [default]);`, where the square brackets denotes `default` is an optional parameter.

`confirm` pops a window containing `OK, CANCEL` - and stores a boolean as the returned value.

### Type Conversions

Sometimes happens automatically, for example by calling `alert`. \
A common type is string conversions - simple done by the `String(value)` function. For example:

```js
let value = true;
value = String(value);  // now value is "true"
```

Another type is numeric conversion - using the `Number(value)` function. 

```js
alert( Number("   123   ") ); // 123
alert( Number("123z") );      // NaN (error reading a number at "z")
alert( Number(true) );        // 1
alert( Number(false) );       // 0
```

In a similar manner, theres also the `Boolean(value)` function, which converts numbers or strings to boolean. 

### Basic Operators

Trivial math operators: `+ - * / % **` and bitwise operators: `& | ^ ~ << >>` and `>>>` - which is a zero-fill right shift.

A special operator is `,` - which allows evaluating multiple expressions, but returning the result only of the last expression. 

```js
let a = (1 + 2, 3 + 4);
alert( a ); // 7 (the result of 3 + 4)
```

This is especially useful within loops initialization definitions:

```js
// three operations in one line
for (a = 1, b = 3, c = a * b; a < 10; a++) {
 ...
}
```

### Comparisons

Numbers comparison is trivial. \
String comparison is done by lexicographical order. 
Different types cause implicit conversions to perform the comparison. 

Strict equality solves the problem of such implicit casts. For example:

```js
alert( 0 == false ); // true
alert( '' == false ); // true
```

If we would like to differentiate `0` from `false`, we would need the strict equality operator - `===`. 













[ECMA-262]: https://ecma-international.org/publications-and-standards/standards/ecma-262/
[MDN]: https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference
