pushd buildroot
cp ../.config .
touch defconfig
make savedefconfig
make BR2_LINUX_KERNEL_DEFCONFIG=x86_64 BR2_EXTERNAL=../kernel_module all
popd
