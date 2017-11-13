# qemu_eclipse

## Required additional packages

> sudo apt-get install git libglib2.0-dev libfdt-dev libpixman-1-dev zlib1g-dev
> 
> sudo apt-get install libnfs-dev libiscsi-dev

## Building

> ./configure --target-list=x86_64-softmmu,x86_64-linux-user,i386-linux-user --disable-xen --disable-vnc --disable-vnc-png --disable-vnc-jpeg --disable-vnc-sasl --disable-blobs --disable-bluez --disable-bsd-user
> 
>make

## Install

> sudo make install

## Command line options

_qemu-x86_64 [-M instruction] [-j/c/rpath path] [-enable-coarse/fine-CFI] [-ss/tss] [-encrypt]_

_-M instruction_

&emsp&emsp **monitor jmp/call/ret instruction and output information**

_-jpath path_

&emsp&emsp **set jmp CFG file path**

_-cpath path_

&emsp&emsp **set call CFG file path**

_-rpath path_

&emsp&emsp **set ret CFG file path**

_-enable-coarse-CFI_

&emsp&emsp **enable Coarse-grained CFI mechanism**

_-enable-fine-CFI_

&emsp&emsp **enable Fine-grained CFI mechanism**

_-ss_

&emsp&emsp **set shadow stack mechanism**

_-tss_

&emsp&emsp **set traditional shadow stack mechanism**

_-encrypt_

&emsp&emsp **encrypt return address**

## Simple test
         
#qemu help

> qemu-x86_64 --help
> 
> #Coarse-Grained CFI test
> 
>qemu-x86_64 -M jmp -fpath *.call/*.func [elf]
