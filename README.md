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

- **monitor jmp/call/ret instruction and output information**

_-jpath path_

- **set jmp CFG file path**

_-cpath path_

- **set call CFG file path**

_-rpath path_

- **set ret CFG file path**

_-enable-coarse-CFI_

- **enable Coarse-grained CFI mechanism**

_-enable-fine-CFI_

- **enable Fine-grained CFI mechanism**

_-ss_

- **set shadow stack mechanism**

_-tss_

- **set traditional shadow stack mechanism**

_-encrypt_

- **encrypt return address**

## Simple test
         
qemu help

> _qemu-x86_64 --help_

Execute a linux process with QEMU

> _qemu-x86_64 xxx_

You can monitor jmp instruction and enable coarse-grained CFI, note you should to append CFG file path with _-jpath_ command 

> _qemu-x86_64 -M jmp -jpath path -enable-coarse-CFI xxx_

You can turn on shadow stack mechanism

> _qemu-x86_64 -ss_















