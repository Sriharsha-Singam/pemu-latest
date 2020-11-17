#!/bin/bash

set -e

# Get Packages
sudo sed -i 's/# deb-src/deb-src/' /etc/apt/sources.list
sudo apt-get install libglib2.0-dev libfdt-dev libpixman-1-dev zlib1g-dev libnfs-dev libiscsi-dev libsdl2-dev linux-headers-$(uname -r) -y
sudo apt-get build-dep qemu -y

# Build Linux.c
pushd task-info
sudo make
sudo insmod task-info.ko
#sudo modprobe ./task-info.ko
sudo dmesg >> temp.txt
cat linux_part1.patch > linux.c
cat temp.txt >> linux.c
cat linux_part2.patch >> linux.c
cat linux.c
popd


# Build QEMU Part
mkdir -p qemu/build
pushd qemu/build
sudo ../configure --prefix=`pwd` --target-list=i386-softmmu --disable-vnc --disable-strip --disable-werror --enable-sdl --enable-debug
sudo make
sudo make install
popd

# Build ELF-PARSER
mkdir -p disas/elf-parser/build
pushd disas/elf-parser/build
../configure
make
popd

# Build PEMU
pushd plugins
mkdir build
make
popd
