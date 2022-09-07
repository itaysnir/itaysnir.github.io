---
layout: post
title:  "Linux Kernel Development Tips"
date:   2022-09-06 19:59:43 +0300
categories: jekyll update
---

# Clone your desired kernel tree

Pretty straightforward:
{% highlight bash %}
git clone "github-repo" "KDIR"
{% endhighlight %}


# Create .config file

Personally, i highly discourage using "make menuconfig". 
This method includes way too many useless drivers, and significally increases compilation time. 

Instead, i sugget using:
{% highlight bash %}
make localmodconfig
{% endhighlight %}
Which configurates only the currently loaded modules (on the host machine), as stated by lsmod. 

It is possible to further reduce the amount of compiled modules, by issuing an lsmod at the VM, and saving this file:
{% highlight bash %}
target$ lsmod > /tmp/mylsmod
target$ scp /tmp/mylsmod host:/tmp
host$ make LSMOD=/tmp/mylsmod localmodconfig
{% endhighlight %}

(yes, i know many images dont contain scp by default. We will handle this soon, dont worry).

Another good alternative, is using:
{% highlight bash %}
make allnoconfig
{% endhighlight %}
And manually enable few of the desired modules, as stated [in this great post][great-post].

To avoid any pem certificate crap (that might cause compilation failure), disable the following config attribute:
{% highlight bash %}
<KDIR>/scripts/config --set-str SYSTEM_TRUSTED_KEYS ""
{% endhighlight %}



# Compile

I suggest having at least 4 cores on your compilation machine:
{% highlight bash %}
ncores
{% endhighlight %}

To reduce compilation time, compile the kernel only for your desired arch (assuming x86), with ncores + 1 threads:
{% highlight bash %}
# within <KDIR>:
make ARCH=x86 -j 5
sudo make -j 5 modules_install
{% endhighlight %}

Note - a compilation of the selected kernel modules is needed. 

Hooray! our lovely kernel now resides at the boot directory: 
{% highlight bash %}
<KDIR>/arch/x86/boot/bzImage
{% endhighlight %}



# Building file system image

[great-post]: https://blog.nelhage.com/2013/12/lightweight-linux-kernel-development-with-kvm/
