# qemu_eclipse

Building

    sudo apt-get install git libglib2.0-dev libfdt-dev libpixman-1-dev zlib1g-dev

    sudo apt-get install libnfs-dev libiscsi-dev

    ./configure --target-list=x86_64-softmmu,x86_64-linux-user,i386-linux-user --disable-xen --disable-vnc --disable-vnc-png --disable-vnc-jpeg --disable-vnc-sasl --disable-blobs --disable-bluez --disable-bsd-user

    make


Install

    sudo make install

Running
         
    #64bits model

    qemu-x86_64 EXE [arg1][arg2]...
