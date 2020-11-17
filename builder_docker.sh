#!/bin/bash

# Build QEMU Part
mkdir -p qemu/build
pushd qemu/build
../configure --prefix=`pwd` --target-list=i386-softmmu --disable-vnc --disable-strip --disable-werror --enable-sdl --enable-debug && make -j6 && make install
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
