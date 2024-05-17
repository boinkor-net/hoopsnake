# Hoopsnake initramfs package

## Building & installing
1. Build hoopsnake, `go build -o hoopsnake cmd/hoopsnake/main.go`
2. Copy files from `ubuntu/etc/hoopsnake/initramfs` and `ubuntu/usr/share/initramfs-tools` to their respective locations in the FHS.
3. Edit `/usr/share/initramfs-tools/conf-hooks.d/hoopsnake` to configure the options used when building initrd.
4. Edit `/etc/hoopsnake/initramfs/hoopsnake.conf` to configure the hoopsnake runtime options.
5. Rebuild initramfs by calling `update-initramfs -u -k all`

## Remove from initrd
1. Delete the files copied in install step 2.
2. Rebuild initramfs by calling `update-initramfs -u -k all`