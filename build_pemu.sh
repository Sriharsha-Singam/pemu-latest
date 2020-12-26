#Build PEMU

set -e
mkdir -p build
pushd build
sudo ../qemu/configure --prefix=`pwd` --target-list=i386-softmmu --disable-vnc --disable-strip --disable-werror --enable-sdl --enable-debug
sudo make
sudo make install
popd
