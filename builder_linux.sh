#!/bin/bash

set -x

# Get Packages
set -e
sudo sed -i 's/# deb-src/deb-src/' /etc/apt/sources.list
sudo apt-get update
sudo apt-get install libglib2.0-dev libfdt-dev libpixman-1-dev zlib1g-dev libnfs-dev libiscsi-dev libsdl2-dev linux-headers-$(uname -r) -y
sudo apt-get build-dep qemu -y
set +e

## Build Linux.c
#pushd task-info
#sudo make
#sudo echo 1 > /proc/sys/kernel/sysrq
#sudo echo x > /proc/sysrq-trigger
#sudo insmod task-info.ko
#sudo modprobe ./task-info.ko
#sudo dmesg --time-format notime | grep -iC 2 "offset of mm" > linux_task_info.patch
#cat ../linux_part1.patch > ../linux.c
#cat linux_task_info.patch >> ../linux.c
#cat ../linux_part2.patch >> ../linux.c
#cat ../linux.c
#popd

# Build QEMU Part
set -e
mkdir -p qemu/build
pushd qemu/build
sudo ../configure --prefix=`pwd` --target-list=i386-softmmu --disable-vnc --disable-strip --disable-werror --enable-sdl --enable-debug
sudo make
sudo make install
popd

# Build ELF-PARSER
#mkdir -p pemu-disas/elf-parser/build
#pushd pemu-disas/elf-parser/build
#sudo ../configure
#sudo make
#popd

# Build PEMU
pushd plugins
mkdir -p build
sudo make
popd

# Build Linux Kernel
pushd buildroot
cp ../.config .
touch defconfig
make savedefconfig
make BR2_LINUX_KERNEL_DEFCONFIG=x86_64 BR2_EXTERNAL=../kernel_module all
popd
