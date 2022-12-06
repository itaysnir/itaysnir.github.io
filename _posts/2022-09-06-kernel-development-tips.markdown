---
layout: post
title:  "Linux Kernel Development Tips"
date:   2022-09-06 19:59:43 +0300
categories: jekyll update
---

**Contents**
* TOC
{:toc}
## IDE


Vim + cscope.

My .vimrc cscope config:
```bash
if has("cscope")
        " Look for a 'cscope.out' file starting from the current directory,
        " going up to the root directory.
        let s:dirs = split(getcwd(), "/")
        while s:dirs != []
                let s:path = "/" . join(s:dirs, "/")
                if (filereadable(s:path . "/cscope.out"))
                        execute "cs add " . s:path . "/cscope.out " . s:path . " -v"
                        break
                endif
                let s:dirs = s:dirs[:-2]
        endwhile

        set csto=0  " Use cscope first, then ctags
        set cst     " Only search cscope
        set csverb  " Make cs verbose
    " To do the first type of search, hit 'CTRL-\' (]?), followed by one of the
    " cscope search types above (s,g,c,t,e,f,i,d).  The result of your cscope
    " search will be displayed in the current window.  You can use CTRL-T to
    " go back to where you were before the search.
    "
        nmap <C-\>s :cs find s <C-R>=expand("<cword>")<CR><CR>
        nmap <C-\>g :cs find g <C-R>=expand("<cword>")<CR><CR>
        nmap <C-\>c :cs find c <C-R>=expand("<cword>")<CR><CR>
        nmap <C-\>t :cs find t <C-R>=expand("<cword>")<CR><CR>
        nmap <C-\>e :cs find e <C-R>=expand("<cword>")<CR><CR>
        nmap <C-\>f :cs find f <C-R>=expand("<cfile>")<CR><CR>
        nmap <C-\>i :cs find i ^<C-R>=expand("<cfile>")<CR>$<CR>
        nmap <C-\>d :cs find d <C-R>=expand("<cword>")<CR><CR>

    " Using 'CTRL-spacebar' (intepreted as CTRL-@ by vim) then a search type
    " makes the vim window split horizontally, with search result displayed in
    " the new window.
    "
        nmap <C-@>s :vert scs find s <C-R>=expand("<cword>")<CR><CR>
        nmap <C-@>g :vert scs find g <C-R>=expand("<cword>")<CR><CR>
        nmap <C-@>c :vert scs find c <C-R>=expand("<cword>")<CR><CR>
        nmap <C-@>t :vert scs find t <C-R>=expand("<cword>")<CR><CR>
        nmap <C-@>e :vert scs find e <C-R>=expand("<cword>")<CR><CR>
        nmap <C-@>f :vert scs find f <C-R>=expand("<cfile>")<CR><CR>
        nmap <C-@>i :vert scs find i ^<C-R>=expand("<cfile>")<CR>$<CR>
        nmap <C-@>d :vert scs find d <C-R>=expand("<cword>")<CR><CR>

        nmap <F6> :cnext <CR>
        nmap <F5> :cprev <CR>

        " Open a quickfix window for the following queries.
        set cscopequickfix=s-,c-,d-,i-,t-,e-,g-
endif
```


## Clone The Kernel Git Repository

```bash
git clone git://git.kernel.org/pub/scm/linux/kernel/git/stable/linux-stable.git
cd linux-stable
git checkout v6.1.8
```

To update the repo, issue `git pull`. 

## Create .config file

Personally, i highly recommend using `make olddefconfig`. 

Another option is using `make menuconfig`. \
This method is manual, and by default includes way too many useless drivers, as well as significally increases compilation time. 

Another possibility:

```bash
make mrproper  # revert any made changes
make localmodconfig
```

Which configurates only the currently loaded modules (on the host machine), as stated by lsmod. 

It is possible to further reduce the amount of compiled modules, by issuing an lsmod at the VM, and saving this file:

```bash
target$ lsmod > /tmp/mylsmod
target$ scp /tmp/mylsmod host:/tmp
host$ make LSMOD=/tmp/mylsmod localmodconfig
```

(yes, i know many images dont contain scp by default. We will handle this soon by integrating scp to our disk image, dont worry).

Another alternative, is using:

```bash
make allnoconfig
```

And manually enable few of the desired modules, as stated [in this great post][great-post].

### Config File Changes 

To avoid any pem certificate compilation errors, disable the following config attribute:

```bash
<KDIR>/scripts/config --set-str SYSTEM_TRUSTED_KEYS ""
```


## Compile

Since we're gonna create our custom kernel and tweak it, I highly suggest giving an indicative name for it.

Open the kernel's `Makefile`, and under the `EXTRAVERSION` attribute, add your dedicated kernel name:
```bash
# SPDX-License-Identifier: GPL-2.0
VERSION = 5
PATCHLEVEL = 4
SUBLEVEL = 0
EXTRAVERSION = maio
NAME = Kleptomaniac Octopus
```


I suggest having at least 4 cores on your compilation machine (simply issue `ncpus` to check the cores count). 

To reduce compilation time, compile the kernel only for your desired arch (assuming x86), with `ncpus` + 1 threads:
```bash
# within <KDIR>:
make ARCH=x86 -j $(( $(ncpus) + 1 ))
```

Hooray! our lovely kernel now resides at the boot directory: 
```bash
<KDIR>/arch/x86/boot/bzImage
```

This binary is the same as the so-called `vmlinuz` file, which is the compressed kernel image.

The uncompressed binary, `vmlinux`, resides within `<KDIR>`. 
It contains many debug symbols, and might be very useful for debugging. 


Afterwards, compile the selected kernel modules:
```bash
make modules_install
```
This will add the compiled modules towards `/lib/modules/<KVER>`. 
Note that in case `KVER` already exists, the existing modules will be overriden. 

Lastly, issue the following command to create an initrd.img, and to set the grub bootloader configuration: 
```bash
make install
```
Note: it does NOT set the newly created kernel as the default boot OS, only adds it as an another boot option.


## Building file system image


### QEMU
One option is to use Yocto images. You can easily find pre-compiled images at: [yocto images][yocto-images] (choose .ext4 image).

However, i find working with debian images abit easier, as it is very easy to deploy packages (such as toolchains) into them. 
An awesome tool for this is `debootstrap`, which downloads a desired debian image, with many options (such as adding packages). 
The following command installs "jessie" debian image, with open-ssh (for ssh + scp) and build-essential (for gcc):
```bash
sudo debootstrap --include=openssh-server,build-essential jessie jessie_dir
```

After the image has downloaded, you can tweak the filesystem as you wish. As said within this [great post][great-post], it will be convenient to disable root password, as well as configuring a getty and network interface (his example code is recommended!). 

In order to make an .ext4 image, run the following commands:
```bash
dd if=/dev/zero of=jessie.img bs=1M seek=4095 count=1
mkfs.ext4 -F jessie.img
sudo mkdir -p /mnt/jessie
sudo mount -o loop jessie.img /mnt/jessie
sudo cp -a jessie_dir/. /mnt/jessie/.
sudo umount /mnt/jessie
sudo rm -rf /mnt/jessie
```

And finally, execute Qemu:
```bash
qemu-system-"$ARCH" \
    -kernel bzImage \
    -drive file=jessie.ext4,if=virtio,format=raw \
    -append "root=/dev/vda rw nokaslr" \
    -m 1024 \
    -s \
    -net nic,model=virtio,macaddr=52:54:00:12:34:56 \
    -net user,hostfwd=tcp:127.0.0.1:4444-:22
```

Notes: 
1. The file system device should be mounted with "rw", otherwise the .ext4 drive of our lovely VM's FS image will be read-only!

2. Flag -m 1024 determines 1024 MB of RAM. Might be insufficient tho.

3. Flag -s is crucial for gdb debugging. nokaslr also makes life easier. 

4. It is possible to SSH the qemu-VM via host port 4444. 
We can now easily transfer files, as we installed scp. 

Full script that might be useful:


```bash
#!/bin/bash

set -euxo pipefail


ARCH="x86_64"

KDIR="$HOME/projects/maio_rfc"
BZIMAGE="${KDIR}/arch/${ARCH}/boot/bzImage"
DEBIAN_SUITE="jessie"
DEBIAN_FS="${KDIR}/tools/itay/jessie"
DEBIAN_IMG="${DEBIAN_FS}.img"
MAIO_FILES="${KDIR}/tools/lib/maio"

if [ $# -ge 1 ] && [ "$1" = "build-fs" ]; then
        if [ ! -d ${DEBIAN_FS} ]; then
                sudo mkdir -p ${DEBIAN_FS}
                sudo debootstrap --include=openssh-server,build-essential \
                        ${DEBIAN_SUITE} ${DEBIAN_FS}

                sudo sed -i '/^root/ { s/:x:/::/ }' ${DEBIAN_FS}/etc/passwd
                echo 'V0:23:respawn:/sbin/getty 115200 hvc0' | sudo tee -a ${DEBIAN_FS}/etc/inittab
                printf '\nauto eth0\niface eth0 inet dhcp\n' | sudo tee -a ${DEBIAN_FS}/etc/network/interfaces
                sudo rm -rf ${DEBIAN_FS}/root/.ssh/
                sudo mkdir ${DEBIAN_FS}/root/.ssh/
                cat ~/.ssh/id_?sa.pub | sudo tee ${DEBIAN_FS}/root/.ssh/authorized_keys

                sudo cp -r ${MAIO_FILES} ${DEBIAN_FS}/root/
        fi


        dd if=/dev/zero of=${DEBIAN_IMG} bs=1M seek=4095 count=1
        mkfs.ext4 -F ${DEBIAN_IMG}
        sudo mkdir -p /mnt/jessie
        sudo mount -o loop ${DEBIAN_IMG} /mnt/jessie
        sudo cp -a ${DEBIAN_FS}/. /mnt/jessie/.
        sudo umount /mnt/jessie
        sudo rm -rf /mnt/jessie
fi

#       -nographic \
#       -append "root=/dev/vda loglevel=15 console=hvc0 nokaslr" \

qemu-system-"$ARCH" \
        -kernel ${BZIMAGE} \
        -drive file=${DEBIAN_IMG},if=virtio,format=raw \
        -append "root=/dev/vda rw nokaslr" \
        -m 1024 \
        -s \
        -net nic,model=virtio,macaddr=52:54:00:12:34:56 \
        -net user,hostfwd=tcp:127.0.0.1:4444-:22

```


### Real HW

The following code snippet compiles and sets my project's adjusted kernel:
```bash
#!/bin/bash

set -exuo pipefail


# Configure these, if needed
KDIR="/homes/itaysnir/projects/maio/maio_rfc"
ARCH="x86"


sudo -i
cd ${KDIR}

make olddefconfig
make modules -j $(( $(ncpus) + 1 ))
make ARCH=${ARCH} -j $(( $(ncpus) + 1 ))
make modules_install
make install
```

Note: `make modules_install` creates the required modules under `/lib/modules/<KVER>`.

`make install` creates an initrd image under the `/boot` directory, and saves the generated `.config` file and `System.map` file under `/boot`.

Finally, it updates the `grub` configuration (However - it doesn't set our new kernel as the default boot option). 


Grub configuration update & set booting kernel (only for the next time):
```bash
sudo update-grub
sudo grub-reboot <VERSION_NAME> && reboot
```

Print grub menuentries for all compiled kernels:
```bash
grub-mkconfig | grep -iE "menuentry 'Ubuntu, with Linux" | awk '{print i++ " : "$1, $2, $3, $4, $5, $6, $7}'
```


## And of course, practice!


I highly suggest the linux-kernel official labs for training:
[linux teaching labs][linux-teaching-labs].

These labs are aimed towards students who are familar with basics of operating systems. 
If you have completed a basic OS course from university, or have familar knowledge about OS, this resource is for you. 

When I will have some spare time, i will post detailed solutions to these labs.

Cya later!

[great-post]: https://blog.nelhage.com/2013/12/lightweight-linux-kernel-development-with-kvm/
[linux-teaching-labs]: https://linux-kernel-labs.github.io/refs/heads/master/labs/introduction.html
[yocto-images]: https://downloads.yoctoproject.org/releases/yocto/yocto-2.3/machines/qemu/qemux86-64/
