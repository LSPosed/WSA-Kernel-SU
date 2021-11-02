# WSA-Kernel-SU

## Intro

This is a kernel module to provide `/system/xbin/su` to Android Kernel (especially to WSA).
This is the best root solution if hiding is required. When GKI is ready, kernelsu is definitely the next generation of root.

Only works on 4.17+ kernel (both WSA and GKI is 5.0+). For older kernel, you can refer to the [origin repo](https://git.zx2c4.com/kernel-assisted-superuser).

## How it works
- Replace syscall `newfstatat`, `faccessat` and `execve` on `/system/xbin/su` to `/system/bin/sh`
- When `execve` on `/system/xbin/su`, change SELinux to permissive, set all kinds of uids and gids to 0 and permit all capabilities
- Set SELinux context `su` to permissive
- Set the selinux context of the current process to `u:r:su:s0`

## License
GPLv2

## Credits
Jason A. Donenfeld for the original implementation
