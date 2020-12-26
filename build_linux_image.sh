# Build Linux Kernel
git clone https://github.com/Sriharsha-Singam/buildroot.git --recurse-submodules
pushd buildroot
git checkout 2020.11.x --recurse-submodules
cp ../.config .
touch defconfig
make savedefconfig
make BR2_LINUX_KERNEL_DEFCONFIG=x86_64 BR2_EXTERNAL=../kernel_module all
popd
