---
layout: post
title: "Java Serialization Vulns"
date: 2025-02-27 21:59:45 +0300
categories: jekyll update
---

**Contents**
* TOC
{:toc}
## Java Serialization 

Java serialization is a mechanism to transform an object into byte stream. \
Recall Java objects are stored in memory, and removed by the GC. We might want to transfer an object - for instance, store it on the disk, or send it over the network. Hence, it needs to be converted into a byte stream. \
To make certain class as serializable, it needs to implement the `Serializable` interface. Under the hood, it uses Java-reflection to crop data from the object's fields (including `private`, `final`). If a field is an object, it would also get serialized, recursively. Notice - getters / setters are not used during the serialization process. \
On the opposite direction, it uses reflection to write data back to an empty object fields. 

## Vulnerabilities

If we can insert modified serialized object, RCE may be triggered. \
In particular, **because the deserialization process doesn't uses the CTOR to forge the object, any validation checks done there are never called**. \
For example:

```java
import java.io.Serializable;
import java.io.FileOutputStream;
import java.io.ObjectOutputStream;


public class ValueObject implements Serializable {

   private String value;
   private String sideEffect;

   public ValueObject() {
       this("empty");
   }

   public ValueObject(String value) {
       this.value = value;
       this.sideEffect = java.time.LocalTime.now().toString();
   }

	public static void main(String[] args)
	{
		try {
		ValueObject vo1 = new ValueObject("Hi");
		FileOutputStream fileOut = new FileOutputStream("ValueObject.ser");
		ObjectOutputStream out = new ObjectOutputStream(fileOut);
		out.writeObject(vo1);
		out.close();
		fileOut.close();
		}
		catch(Exception e) {
		}
	}
}
```

After compiling and running the above program, the serialized object has been created on-disk:

```bash
$ hexdump -C ValueObject.ser
00000000  ac ed 00 05 73 72 00 0b  56 61 6c 75 65 4f 62 6a  |....sr..ValueObj|
00000010  65 63 74 44 ed 38 08 74  6c 6b fe 02 00 02 4c 00  |ectD.8.tlk....L.|
00000020  0a 73 69 64 65 45 66 66  65 63 74 74 00 12 4c 6a  |.sideEffectt..Lj|
00000030  61 76 61 2f 6c 61 6e 67  2f 53 74 72 69 6e 67 3b  |ava/lang/String;|
00000040  4c 00 05 76 61 6c 75 65  71 00 7e 00 01 78 70 74  |L..valueq.~..xpt|
00000050  00 12 32 30 3a 33 35 3a  30 33 2e 38 32 34 39 36  |..20:35:03.82496|
00000060  37 39 30 30 74 00 02 48  69                       |7900t..Hi|
00000069
```

Notice how the `"Hi"` string is encoded by the end of the serialized object. We can tamper this to some value of our wish, hence - effectively changing the corresponding member value. \
But one step further than just tampering with data, we can obtain RCE!

## Gadgets

Gadgets are simply classes / functions that already exists within the executable code (similar to ROP gadgets). Meaning, it can be reused for malicious purposes. \
During the deserialization process, some magic methods of the `Serializable` interface are being called implicitly. One such example is the `readObject` method, which reflectively gets called when desserializing. Example gadget, and overwrite of `readObject`: 

```java
import java.io.IOException;
import java.io.ObjectInputStream;

public class Gadget {
   private Runnable command;

   public Gadget(Command command) {
       this.command = command;
   }

   private final void readObject(ObjectInputStream in) throws IOException, ClassNotFoundException {
       in.defaultReadObject();
       command.run();
   } 
}
```

Now every time an object of `Gadget` class gets serialized, it would issue `readObject`, and execute `command.run()`. In particular:

```java
public class Command implements Runnable, Serializable {

   private String command;

   public Command(String command) {
       this.command = command;
   }

   @Override
   public void run() {
       try {
           Runtime.getRuntime().exec(command);
       } catch (IOException e) {
           throw new RuntimeException(e);
       }
   }
```

Now, upon reading the serialized bytes, the following would execute arbitrary code:

```bash
FileInputStream fileIn = new FileInputStream("Gadget.ser");
ObjectInputStream in = new ObjectInputStream(fileIn);
var obj = (ValueObject)in.readObject();
```

## Chains

Similar to ROP-chains, made of gadgets. \
In real world, a good approach is to exploit using `java.util.HashMap`, as it has a custom implementation of `readObject`, which triggers every `key`'s `hashcode` function. \
Moreover, just as ROP chains may also be forged using libc (and ANY other loaded library for the process), the same happens here - we may execute chain of gadgets from external libraries. Log4Shell could have originated from Java's native serialization framework. 

## Prevention

If the app doesn't accepts serialized objects, it cant hurt. \
However, if the `Serializable` interface is implemented (due to inheritance for example), we can overwrite `readObject`, such that it would throw an exception upon a deserialization attempt. \
Java lso supports `ValidatedObjectInputStream` (to explicitly allow which objects are allowed to be deserialized) and serialization filters. 

## Surface

Notice - java serialization vulns are not exclusive to Java's custom serialization mechanism. Vulns also exist in serialization / marshalling frameworks, such as creating objects from XML, JSON, yaml, etc. \
Example: consider a website that uses a serialized object to store data about user's session. If an attacker spotted this serialized object in an HTTP request, they may tamper this value, creating a custom serialized object. \
We can pass in object of any serializable class that is available to the website's process, and the object will be deserialized. Hence, it allows attacker to create instances of arbitrary classes. In particular, attacker could look for classes containing deserialization magic methods (`readObject`), and check if any of them does interesting logic on a controllable data. 


TODO: add code snippets from CERT

